#!/usr/bin/env python3

import asyncio
import argparse
import sys
import time
import socket
import random
from loguru import logger

from network import Address
from network import BTC_PORT
from network import MinimalNode

DNS_PORT = 53
DNS_SEEDS = [
        'seed.bitcoin.sipa.be',
        'dnsseed.bluematt.me',
        'dnsseed.bitcoin.dashjr.org',
        'seed.bitcoinstats.com',
        'seed.bitcoin.jonasschnelli.ch',
        'seed.btc.petertodd.org',
        'seed.bitcoin.sprovoost.nl',
        'dnsseed.emzy.de',
        ]

class Crawler:
    def __init__(self, percentage, user_agent_stats):
        self.active = set()
        self.unreachable = set()
        self.pending = set()
        self.percentage = percentage
        self.num_active_crawlers = 0
        self.user_agents = {}
        self.user_agent_stats = user_agent_stats

    def bootstrap_nodelist(self):
        for dns_seed in DNS_SEEDS:
            try:
                hosts = socket.getaddrinfo(dns_seed, DNS_PORT, proto=socket.IPPROTO_TCP)
            except:
                logger.warning(f'error getting seeds from {dns_seed}')
                continue
            for host in hosts:
                # fifth tuple is (ip, port)
                # use only ip, for port is wrongly reported as 53
                self.pending.add(Address(host[4][0], BTC_PORT))

        logger.info(f'discovered {len(self.pending)} unique nodes via DNS seeds')

    async def connect(self, node):
        # get node's peers
        logger.trace(f'trying to open connection to {node}')
        connection = MinimalNode(node)
        await connection.establish(timeout=3)
        await connection.handshake(self.user_agents)
        return connection

    async def crawler(self):
        self.num_active_crawlers += 1
        while True:
            # stop if no pending nodes left
            if not self.pending:
                self.num_active_crawlers -= 1
                return

            # get random node from set of pending nodes
            node = random.sample(self.pending, 1)[0]
            self.pending.remove(node)

            # try to connect to node
            try:
                connection = await self.connect(node)
            except (ConnectionRefusedError, RuntimeError, OSError, asyncio.IncompleteReadError) as e:
                logger.debug(f'error with connection to node {node} (reason: {e})')
                self.unreachable.add(node)
                continue
            except (TimeoutError, asyncio.TimeoutError):
                logger.debug(f'error with connection to node {node} (reason: Timeout)')
                self.unreachable.add(node)
                continue

            # if successful, add node to set of active nodes
            logger.debug(f'successfully connected to node {node}')
            self.active.add(node)

            # When desired, only ask some nodes for peers to speed up crawling
            if random.random() > self.percentage:
                await connection.close()
                continue

            # Ask current node for peers and close connection
            try:
                peers = await connection.get_peers()
            except (ConnectionRefusedError, RuntimeError, OSError, asyncio.IncompleteReadError) as e:
                logger.debug(f'error with connection to node {node} (reason: {e})')
                self.unreachable.add(node)
                continue
            except (TimeoutError, asyncio.TimeoutError):
                logger.debug(f'error with connection to node {node} (reason: Timeout)')
                self.unreachable.add(node)
                continue
            await connection.close()

            # identify eligible nodes
            num_eligible_nodes = 0
            num_known_nodes = 0
            num_stale_nodes = 0
            threshold = int(time.time()) - (24*60*60)
            for peer in peers:
                # discard known peers
                if peer in self.active or peer in self.unreachable or peer in self.pending:
                    num_known_nodes += 1
                    continue
                # discard peers older than one day
                if peer.timestamp < threshold:
                    num_stale_nodes += 1
                    continue
                # add remaining nodes to set of univisted nodes
                num_eligible_nodes += 1
                self.pending.add(peer)
            logger.debug(f'received {num_eligible_nodes} eligible peer(s) from {node} (total: {len(peers)} stale: {num_stale_nodes} known: {num_known_nodes})')

    async def monitor(self):
        while True:
            # stop if no pending nodes left
            if not self.pending and self.num_active_crawlers == 0:
                return

            logger.info(f'active: {len(self.active)} (pending: {len(self.pending)} unreachable: {len(self.unreachable)})')
            await asyncio.sleep(5)


    async def crawl_nodes(self):
        # create coroutines
        NUM_COROUTINES = 20
        tasks = [self.crawler() for _ in range(NUM_COROUTINES)]
        tasks.append(self.monitor())

        # schedule coroutines
        started = time.time()
        await asyncio.gather(*tasks)

        # output results
        logger.info(f'[RESULT] active: {len(self.active)} unreachable: {len(self.unreachable)} runtime: {time.time()-started:.1f}s - percentage: {self.percentage}')
        logger.info(f'[RESULT] User agent composition: {self.user_agents}')

        # pickle user-agent statistics if requested
        if self.user_agent_stats:
            import pickle
            from datetime import datetime
            now = datetime.now().strftime('%Y-%m-%d-%H.%M')
            filename = f'{now}-perc-{self.percentage}.pkl'
            with open(filename, 'wb') as fp:
                pickle.dump(self.user_agents, fp, protocol=pickle.HIGHEST_PROTOCOL)

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--percentage', type=float, required=False, default=0.2, action='store', help='Percentage of nodes to query for peers')
parser.add_argument('-u', '--useragents', type=bool, required=False, default=True, action='store', help='Store dict containing user-agent statistics')
args = parser.parse_args()

crawler = Crawler(percentage=args.percentage, user_agent_stats=args.useragents)
crawler.bootstrap_nodelist()
asyncio.run(crawler.crawl_nodes())
