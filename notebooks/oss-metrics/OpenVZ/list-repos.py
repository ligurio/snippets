#!/usr/bin/env python
"""
    List all public GIT repositories owned by Virtuozzo
	and GIT repositories of projects where OpenVZ developers participate.
"""

import pygithub3

external = ['git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git',
			'git://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git',
			'git://libvirt.org/libvirt.git',
			'git://repo.or.cz/nasm.git',
			'https://github.com/opencontainers/runc',
			'git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git',
			'https://github.com/file/file',
			'git://git.qemu.org/qemu.git',
			'git://git.kernel.org/pub/scm/virt/kvm/kvm.git',
			'https://github.com/openstack/openstack']

internal = ['https://github.com/xemul/criu',
			'https://github.com/xemul/libct',
			'https://github.com/xemul/p.haul',
			'https://github.com/xemul/mosaic',
			'https://github.com/xemul/compel']

gh_organizations = ['OpenVZ', 'Virtuozzo']

gh = None

def gather_clone_urls(organization, no_forks=True):
    all_repos = gh.repos.list_by_org(organization ,type='all').all()
    for repo in all_repos:

        # Don't print the urls for repos that are forks.
        if no_forks and repo.fork:
            continue
    
        yield repo.clone_url

if __name__ == '__main__':
    gh = pygithub3.Github()

    for org in gh_organizations:
        clone_urls = gather_clone_urls(org)
        for url in clone_urls:
            print url

    for url in external:
		print url

    for url in internal:
		print url
