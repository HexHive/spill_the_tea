#!/usr/bin/python3

import os
from data.config import devices, fw_path
from utils.fw_repo import traverse_dataset, get_ta2dict, get_all_tas, vendor_has_region
import data.samsung_vuln_db as samsung_vulns
import data.xiaomi_vuln_db as xiaomi_vulns
import datetime

"""
numbers to generate:

ODM/TEE | Vendor | nr. devices (region) | nr. FWs | nr. TAs | nr. vulns | nr. TAs with rollback increase | nr TAs with rollback exposure | nr. devices with rollback exposure

"""

data = {}
NEUTR_TIMES = []
NEUTR_TIMES_NEG = []

for vendor, devices in devices.items():
    for device in devices:
        if not vendor_has_region(vendor):
            tee = devices[device]
            if tee not in data:
                data[tee] = {
                    vendor: {
                        "nr_devices": 0,
                        "nr_fw": 0, 
                        "nr_TAs_unique": 0,
                        "nr_TAs": 0,
                        "nr_public_vulns": 0,
                        "nr_vulnerable_tas": 0,
                        "nr_TAs_pp": 0,
                        "nr_TAs_neutralized": 0,
                        "days_neutralized_avg": [],
                        "nr_TAs_rollbackable": 0,
                        "nr_devices_rollbackable": 0
                    }
                }
            else:
                if vendor not in data[tee]:
                    data[tee][vendor] = {
                        "nr_devices": 0,
                        "nr_fw": 0, 
                        "nr_TAs_unique": 0, # nr TAs
                        "nr_TAs": 0,
                        "nr_public_vulns": 0,
                        "nr_vulnerable_tas": 0,
                        "nr_TAs_pp": 0,
                        "nr_TAs_neutralized": 0,
                        "days_neutralized_avg": [],
                        "nr_TAs_rollbackable": 0,
                        "nr_devices_rollbackable": 0
                    }
            # 1 new device
            device_rollbackable = False
            data[tee][vendor]["nr_devices"] += 1
            if not os.path.exists(os.path.join(fw_path, vendor, device)):
                continue
            ta2dict = get_ta2dict(vendor, device)
            v2tas = get_all_tas(vendor, device)
            nr_versions = len(v2tas)
            nr_tas = 0
            for v, tas in v2tas.items():
                 nr_tas += len(tas)
            data[tee][vendor]["nr_TAs"] += nr_tas
            data[tee][vendor]["nr_fw"] += nr_versions
            data[tee][vendor]["nr_TAs_unique"] += len(ta2dict)
            # check for increase: 
            nr_tas = 0
            for ta_name, tas in ta2dict.items():
                ctr_incrased = False
                nr_tas += len(tas)
                print("checking", vendor, device, ta_name, len(tas), tas)
                init_ta_ctr = tas[0].rollback_counter
                for ta in tas:
                    if ta.rollback_counter > init_ta_ctr:
                        data[tee][vendor]["nr_TAs_pp"] += 1
                        ctr_incrased = True
                        break
                vuln_db = xiaomi_vulns.VULNS
                print("checking for vuln: ", ta.get_vuln_name() )
                if ta.get_vuln_name() in vuln_db:
                    vulns = vuln_db[ta.get_vuln_name()]
                    newest_vuln = vulns[0]
                    for vuln in vulns:
                        if datetime.datetime.strptime(vuln[0], '%m/%Y') > datetime.datetime.strptime(newest_vuln[0], '%m/%Y'):
                            newest_vuln = vuln
                    if datetime.datetime.strptime(newest_vuln[1], '%m/%Y') - tas[0].date <  -datetime.timedelta(days=12*30):
                        # time between vuln and first firmware is big enough, probably not relevant
                        pass
                    elif not ctr_incrased:
                        data[tee][vendor]["nr_TAs_rollbackable"] += 1
                        if not device_rollbackable:
                            data[tee][vendor]["nr_devices_rollbackable"] += 1
                            device_rollbackable = True
                    else:
                        neutralized = False
                        for ta in ctr_increaed_list:
                            if ta.date > datetime.datetime.strptime(newest_vuln[0], '%m/%Y'):
                                if not neutralized:
                                    neutralized = True
                                    NEUTR_TIMES.append(ta.date - datetime.datetime.strptime(newest_vuln[1], '%m/%Y'))
                        if not neutralized:
                            data[tee][vendor]["nr_TAs_rollbackable"] += 1
                            if not device_rollbackable:
                                data[tee][vendor]["nr_devices_rollbackable"] += 1
                                device_rollbackable = True 
                        else:
                            data[tee][vendor]["nr_TAs_neutralized"] += 1
                    # estimate how many versions are vulnerable
                    vulns = vuln_db[ta.get_vuln_name()]
                    newest_vuln = vulns[0]
                    for vuln in vulns:
                        if datetime.datetime.strptime(vuln[0], '%m/%Y') > datetime.datetime.strptime(newest_vuln[0], '%m/%Y'):
                            newest_vuln = vuln
                    nr_vulnearble_versions = 0
                    for ta in tas:
                        if datetime.datetime.strptime(newest_vuln[1], '%m/%Y') > ta.date: #disclosure time is greater than time of TA
                            nr_vulnearble_versions += 1
                    data[tee][vendor]["nr_vulnerable_tas"] += nr_vulnearble_versions
        else:
            tee = devices[device]
            if tee not in data:
                data[tee] = {
                    vendor: {
                        "nr_devices": 0,
                        "nr_fw": 0, 
                        "nr_TAs_unique": 0,
                        "nr_TAs": 0,
                        "nr_public_vulns": 0,
                        "nr_vulnerable_tas": 0,
                        "nr_TAs_pp": 0,
                        "nr_TAs_neutralized": 0,
                        "days_neutralized_avg": [],
                        "nr_TAs_rollbackable": 0,
                        "nr_devices_rollbackable": 0
                    }
                }
            else:
                if vendor not in data[tee]:
                    data[tee][vendor] = {
                        "nr_devices": 0,
                        "nr_fw": 0, 
                        "nr_TAs_unique": 0,
                        "nr_TAs": 0,
                        "nr_public_vulns": 0,
                        "nr_vulnerable_tas": 0,
                        "nr_TAs_pp": 0,
                        "nr_TAs_neutralized": 0,
                        "days_neutralized_avg": [],
                        "nr_TAs_rollbackable": 0,
                        "nr_devices_rollbackable": 0
                    }
            device_rollbackable = False
            data[tee][vendor]["nr_devices"] += 1
            if not os.path.exists(os.path.join(fw_path, vendor, device)):
                continue
            for region in os.listdir(os.path.join(fw_path, vendor, device)):
                ta2dict = get_ta2dict(vendor, device, region)
                v2tas = get_all_tas(vendor, device, region)
                nr_versions = len(v2tas)
                data[tee][vendor]["nr_fw"] += nr_versions
                nr_tas = 0
                for v, tas in v2tas.items():
                    nr_tas += len(tas)
                data[tee][vendor]["nr_TAs"] += nr_tas
                data[tee][vendor]["nr_TAs_unique"] += len(ta2dict)
                # check for increase: 
                nr_tas = 0
                for ta_name, tas in ta2dict.items():
                    print("checking", vendor, device, region, ta_name)
                    init_ta_ctr = tas[0].rollback_counter
                    nr_tas += len(tas)
                    ctr_incrased = False
                    ctr_increaed_list = []
                    for ta in tas:
                        if ta.rollback_counter > init_ta_ctr:
                            ctr_increaed_list.append(ta)
                            if not ctr_incrased:
                                data[tee][vendor]["nr_TAs_pp"] += 1
                                ctr_incrased = True
                    # check if theres a associated vulnerability
                    if vendor == "xiaomi":
                        vuln_db = xiaomi_vulns.VULNS
                    else:
                        vuln_db = samsung_vulns.VULNS
                    print("checking for vuln: ", ta.get_vuln_name() )
                    if ta.get_vuln_name() in vuln_db:
                        vulns = vuln_db[ta.get_vuln_name()]
                        newest_vuln = vulns[0]
                        for vuln in vulns:
                            if datetime.datetime.strptime(vuln[0], '%m/%Y') > datetime.datetime.strptime(newest_vuln[0], '%m/%Y'):
                                newest_vuln = vuln
                        #if datetime.datetime.strptime(newest_vuln[1], '%m/%Y') - tas[0].date <  -datetime.timedelta(days=12*30):
                        if datetime.datetime.strptime(newest_vuln[1], '%m/%Y') - tas[0].date <  -datetime.timedelta(days=12*30):
                            # time between vuln and first firmware is big enough, probably not relevant
                            pass
                        elif not ctr_incrased:
                            data[tee][vendor]["nr_TAs_rollbackable"] += 1
                            if not device_rollbackable:
                                data[tee][vendor]["nr_devices_rollbackable"] += 1
                                device_rollbackable = True
                        else:
                            neutralized = False
                            for ta in ctr_increaed_list:
                                if ta.date > datetime.datetime.strptime(newest_vuln[0], '%m/%Y'):
                                    if not neutralized:
                                        neutralized = True
                                        NEUTR_TIMES.append(ta.date - datetime.datetime.strptime(newest_vuln[1], '%m/%Y'))
                                        data[tee][vendor]["days_neutralized_avg"].append((ta.date - datetime.datetime.strptime(newest_vuln[1], '%m/%Y')).days)
                                        if ta.date - datetime.datetime.strptime(newest_vuln[1], '%m/%Y') < datetime.timedelta(minutes=1):
                                            NEUTR_TIMES_NEG.append(("WTF", ta.name, ta.rollback_counter, ta.filepath, ta.date, newest_vuln))
                            if not neutralized:
                                data[tee][vendor]["nr_TAs_rollbackable"] += 1
                                if not device_rollbackable:
                                    data[tee][vendor]["nr_devices_rollbackable"] += 1
                                    device_rollbackable = True 
                            else:
                                data[tee][vendor]["nr_TAs_neutralized"] += 1
                        # estimate how many versions are vulnerable
                        vulns = vuln_db[ta.get_vuln_name()]
                        newest_vuln = vulns[0]
                        for vuln in vulns:
                            if datetime.datetime.strptime(vuln[0], '%m/%Y') > datetime.datetime.strptime(newest_vuln[0], '%m/%Y'):
                                newest_vuln = vuln
                        nr_vulnearble_versions = 0
                        for ta in tas:
                            if datetime.datetime.strptime(newest_vuln[1], '%m/%Y') > ta.date: #disclosure time is greater than time of TA
                                nr_vulnearble_versions += 1
                        data[tee][vendor]["nr_vulnerable_tas"] += nr_vulnearble_versions
                    #data[tee][vendor]["nr_TAs"] += nr_tas
    
# manual cuz bad
data["mediatek"]["xiaomi"]["nr_public_vulns"] = 10
data["teegris"]["samsung"]["nr_public_vulns"] = 12
data["kinibi"]["samsung"]["nr_public_vulns"] = 9
data["qualcomm"]["samsung"]["nr_public_vulns"] = 3

for tee in data:
    for vendor in data[tee]:
        if len(data[tee][vendor]["days_neutralized_avg"]) == 0:
            data[tee][vendor]["days_neutralized_avg"] = 0
        else:
            data[tee][vendor]["days_neutralized_avg"] = sum(data[tee][vendor]["days_neutralized_avg"])/len(data[tee][vendor]["days_neutralized_avg"])

print(NEUTR_TIMES)
print(NEUTR_TIMES_NEG)
if len(NEUTR_TIMES) != 0:
    print("average rollback ctr release after patch:", sum(td.days for td in NEUTR_TIMES)/len(NEUTR_TIMES))

import json

open("numbers.json", "w+").write(json.dumps(data))
