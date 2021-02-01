import itertools
import yaml
import re
from pprint import pprint as pp

class blockseq( dict ): pass
def blockseq_rep(dumper, data):
    return dumper.represent_mapping( u'tag:yaml.org,2002:map', data, flow_style=False )

class flowmap( dict ): pass
def flowmap_rep(dumper, data):
    return dumper.represent_mapping( u'tag:yaml.org,2002:map', data, flow_style=True )

class AccessListEntery():
    def __init__(self, **kwargs) -> None:
        self.raw = kwargs.copy()
        tmp = kwargs.copy()

        self.description = tmp.pop('description', None)
        self.prot = tmp.pop('prot', None)
        self.srcip = tmp.pop('srcip', None)
        self.srcport = tmp.pop('srcport', None)
        self.dstip = tmp.pop('dstip', None)
        self.dstport = tmp.pop('dstport', None)

        self.filename = tmp.pop('filename', None)
        self.dcname = tmp.pop('dcname', None)
        self.pgname = tmp.pop('pgname', None)

        self.remaining = tmp

        hostname_from, hostname_to, protname, is_ret, action = None, None, None, None, None
        m = re.fullmatch(r'([^-]+)-([^_]+)_([^_]+)_(RET_)?(ALLOW)', self.description)
        if m:
            hostname_from, hostname_to, protname, is_ret, action, = m.groups()

        self.hostname_from = hostname_from
        self.hostname_to = hostname_to
        self.protname = protname
        self.is_ret = is_ret
        self.action = action

    @property
    def host_from(self):
        if not self.is_ret:
            return (self.hostname_from, self.srcip)
        else:
            return (self.hostname_from, self.dstip)

    @property
    def host_to(self):
        if not self.is_ret:
            return (self.hostname_to, self.dstip)
        else:
            return (self.hostname_to, self.srcip)

    def to_dict(self):
        tmp = self.raw
        tmp.pop('filename', None)
        tmp.pop('dcname', None)
        tmp.pop('pgname', None)
        return self.raw

class AccessListManager():
    def __init__(self) -> None:
        self.acls = []

    def add_file(self, filename) -> None:
        with open(filename, 'r') as f:
            data = yaml.safe_load(f)
        for dcname, portgroups in data.items():
            for pgname, acls in portgroups.items():
                for acle in acls:
                    self.acls.append(AccessListEntery(**acle, filename=filename, dcname=dcname, pgname=pgname))

    def to_yaml(self) -> str:
        yaml.add_representer(blockseq, blockseq_rep)
        yaml.add_representer(flowmap, flowmap_rep)

        data = {}
        for acle in self.acls:
            data.setdefault(acle.dcname, {})
            data[acle.dcname].setdefault(acle.pgname, [])
            data[acle.dcname][acle.pgname].append(acle)

        for dcname in data.keys():
            for pgname in data[dcname].keys():
                data[dcname][pgname] = [flowmap(x.to_dict()) for x in data[dcname][pgname]]

        return yaml.dump(data, sort_keys=False, width=200)

    @property
    def dcnames(self):
        tmp = [acle.dcname for acle in self.acls]
        return list(dict.fromkeys(tmp))

    @property
    def pgnames(self):
        tmp = [acle.pgname for acle in self.acls]
        return list(dict.fromkeys(tmp))

    @property
    def hosts(self):
        tmp = [[acle.host_from, acle.host_to] for acle in self.acls]
        tmp = itertools.chain.from_iterable(tmp)
        return list(dict.fromkeys(tmp))

    @property
    def hostnames(self):
        tmp = [host[0] for host in self.hosts]
        return list(dict.fromkeys(tmp))

def main():
    alm = AccessListManager()
    alm.add_file("acl.yml")
    # alm.verify()
    print(alm.to_yaml())

    for hostname in alm.hostnames:
        print(hostname)

    for host in sorted(alm.hosts, key=lambda x: x[0]):
        print(host)

    # for rule in alm.rules:
    #     print(rule)

    # for dc in alm.datacenters:
    #     print(dc.name)
    #     for pg in dc.portgroups:
    #         print(pg.name)
    #         for rule in pg.rules:
    #             print(rule)

if __name__ == "__main__":
  main()
