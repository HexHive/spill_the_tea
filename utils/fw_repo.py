from .parse_report import get_tas, get_date
from data.config import fw_path, devices
import datetime
import os
import copy


def vendor_has_region(vendor):
    return not vendor in ["oppo", "vivo", "infinix", "tecno"]


def get_all_tas(vendor, device, region=None):
    # returns the dictionary of all tas sorted by data
    dev_p = os.path.join(fw_path, vendor, device)
    out = {}
    tee = devices[vendor][device]
    if region:
        dev_p = os.path.join(dev_p, region)
    date2info = {}
    for version in os.listdir(dev_p):
        version_p = os.path.join(dev_p, version)
        report = os.path.join(version_p, "report.json")
        date = get_date(report, tee, vendor)
        tas = get_tas(report, tee, vendor)
        if len(tas) > 0:
            date2info[date] = (version, tas)
    out = dict([date2info[datetime.datetime.fromtimestamp(date)] for date in sorted([datetime.datetime.timestamp(dt) for dt in date2info.keys()])])
    return out


def traverse_dataset():
    # {vendor: {device[_region]: {version: [TAs]}}}
    out = {}
    for vendor in devices:
        out[vendor] = {}
        for device in devices[vendor]:
            if vendor_has_region(vendor):
                for region in os.listdir(os.path.join(fw_path, vendor, device)):
                    out[vendor][f'{device}_{region}'] = get_all_tas(vendor, device, region)
            else:
                out[vendor][device] = get_all_tas(vendor, device)
    return out


def get_ta2dict(vendor, device, region=None):
    v2tas = get_all_tas(vendor, device, region)
    out = {}
    for version, tas in v2tas.items():
        for ta in tas:
            if ta.name not in out:
                out[ta.name] = [ta]
            else:
                out[ta.name].append(ta)
    return out



