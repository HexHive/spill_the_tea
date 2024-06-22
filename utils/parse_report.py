import os,json,datetime

class TA:
    def __init__(self, name, rollback_counter, filepath, vendor, tee, date, device):
        self.name = name
        self.rollback_counter = rollback_counter
        self.filepath = filepath
        self.tee = tee
        self.vendor = vendor
        self.date = date
        self.device = device
    def get_vuln_name(self):
        filename = self.filepath.split("/")[-1]
        vuln_name = filename.split(".")[0]
        return vuln_name
    def __repr__(self) -> str:
        return f"TA({self.name},{self.filepath})"
    def __str__(self) -> str:
        return f"TA({self.name},{self.filepath})"
        

def get_tas(report, tee, vendor):
    # path is of type /fw/vendor/device/[region]/version/report.json
    out = []
    #print(report, tee, vendor)
    ta2v = get_ta_version(report, tee, vendor)
    ta2p = get_ta_filepath(report, tee, vendor)
    date = get_date(report, tee, vendor)
    device = report.split("/")[3]
    for ta in ta2v:
        if ta in ta2p:
            out.append(TA(ta, ta2v[ta], ta2p[ta], vendor, tee, date, device))
    return out


def get_date(report_path, tee, vendor):
    ver_dir = os.path.dirname(report_path)
    if vendor == "samsung":
        try:
            metadata = json.load(open(os.path.join(ver_dir, "metadata.json")))
            date = datetime.datetime.strptime(metadata["BUILD_DATE"], "%Y%m%d%H%M%S")
        except:
            date = datetime.datetime.strptime("1970.1.1", "%Y.%m.%d")
        return date
    elif vendor == "xiaomi":
        try:
            metadata = json.load(open(os.path.join(ver_dir, "metadata.json")))
            date = datetime.datetime.strptime(metadata["date"], "%Y-%m-%d")
        except:
            date = datetime.datetime.strptime("1970.1.1", "%Y.%m.%d")
        return date
    elif vendor == "oppo" or vendor == "vivo" or vendor == "tecno" or vendor == "infinix":
        ver_dir = os.path.dirname(report_path)
        version = ver_dir.split("/")[-1]
        try:
            date = datetime.datetime.strptime(version, '%y%m%d')
        except:
            date = datetime.datetime.strptime("1970.1.1", "%Y.%m.%d")
        return date
    else:
        print("UNKNWON VENDOR!!", report_path, vendor)
        exit(-1)


def get_teegris_name(name):
    bytess = name.encode()
    try:
        out = bytess.decode("ascii")
    except:
        out = bytess.hex()
    return out       


def get_ta_version_beanpod(report_path, vendor):
    out = {}
    if vendor == "xiaomi":
        # fw path is /fw/xiaomi/region/version/version/tas
        base_path = os.path.dirname(report_path)
        version = base_path.split("/")[-1]
        if not os.path.exists(os.path.join(base_path, version, "tas")):
            return {}
        for ta in os.listdir(os.path.join(base_path, version, "tas")):
            if not ta.endswith(".ta"):
                continue
            out[ta] = 0
    else:
        # fw path is /fw/device/[region]/version/tas/
        base_path = os.path.dirname(report_path)
        print(base_path)
        for ta in os.listdir(os.path.join(base_path, "tas")):
            if not ta.endswith(".ta"):
                continue
            out[ta] = 0
    return out


def get_ta_version_kinibi(report_path):
    if not os.path.exists(report_path):
        return {}
    out = {}    
    data = json.load(open(report_path))
    for ta in data:
        if "rollback_version" not in ta:
            continue
        out[ta["filename"].split("/")[-1]] = ta["rollback_version"]
    return out


def get_ta_version_qsee(report_path):
    if not os.path.exists(report_path):
        return {}
    data = json.load(open(report_path))
    ci2mdt_field = {
            "old_mdt": {"rollback_nr": "Version", "hw_id": "MSM_ID", "sw_id": "SW_ID", "oem_id": "OEM_ID", "model_id": "MODEL_ID"},
            "new_mdt": {"rollback_nr": "anti_rollback", "hw_id": "hw_id", "sw_id": "sw_id", "oem_id": "oem_id", "model_id": "model_id", "secondary_sw_id": "secondary_sw_id"} 
            }
    out = {}
    for ta in data:
        if ta['old_mdt']:
            field = ci2mdt_field['old_mdt']["rollback_nr"]
            sw_id = ci2mdt_field['old_mdt']["sw_id"]
            if field in ta and ta[sw_id] == 12:
                out[ta["ta_name"]] = ta[field]
        else:
            field = ci2mdt_field['new_mdt']["rollback_nr"]
            secondary_sw_id =  ci2mdt_field['new_mdt']["secondary_sw_id"]
            if field in ta and ta[secondary_sw_id] != 0: # venus has 0 so exclude
                out[ta["ta_name"]] = ta[field]
    return out


def get_ta_version_teegris(report_path):
    if not os.path.exists(report_path):
        return {}
    data = json.load(open(report_path))
    out = {}
    for ta in data:
        if 'sec_version' not in ta:
            continue
        if ta['sec_version'] == 2:
            name = get_teegris_name(ta["human_name"])
            out[name] = 0
        else:
            name = get_teegris_name(ta["human_name"])
            out[name] = ta['rollback_version']
    return out


def get_ta_version(report_path,tee_type, vendor=None):
    if tee_type == "kinibi":
        return get_ta_version_kinibi(report_path)
    elif tee_type == "mediatek" or tee_type =="beanpod":
        return get_ta_version_beanpod(report_path, vendor)
    elif tee_type == "qualcomm" or tee_type == "QSEE" or tee_type == "qsee":
        return get_ta_version_qsee(report_path)
    elif tee_type == "teegris" or tee_type == "mediatek_teegris":
        return get_ta_version_teegris(report_path)
    else:
        print("WTF unkwon tee", tee_type)
        exit(-102)


def find_qsee_ta(ta_name, tas):
    for pot_ta in os.listdir(tas):
        if ta_name in pot_ta and (pot_ta.endswith(".mbn") or pot_ta.endswith(".elf")):
            return os.path.join(tas, pot_ta)
    return None


def get_filepath_xiaomi(report_path, tee):
    if tee == "beanpod" or tee == "mediatek":
        out = {}
        base_path = os.path.dirname(report_path)
        version = base_path.split("/")[-1]
        if not os.path.exists(os.path.join(base_path, version, "tas")):
            return {}
        for ta in os.listdir(os.path.join(base_path, version, "tas")):
            if not ta.endswith(".ta"):
                continue
            out[ta] = os.path.join(base_path, version, "tas", ta)
        return out
    elif tee == "qualcomm":
        if not os.path.exists(report_path):
            return {}
        report = json.load(open(report_path))
        base_path = os.path.dirname(report_path)
        version = base_path.split("/")[-1]
        out = {}
        for ta in report:
            ta_name = ta["ta_name"]
            found = find_qsee_ta(ta_name, os.path.join(base_path, version))
            if found:
                out[ta_name] = found
        return out
    else:
        print("XIAOMI UNSUPPORTED TEE!?!?", report_path, tee)
        exit(-5024)


def get_filepath_infinix_tecno(report_path, tee):
    if tee == "beanpod" or tee == "mediatek":
        base_path = os.path.dirname(report_path)
        out = {}
        if not os.path.exists(os.path.join(base_path, "tas")):
            return {}
        for ta in os.listdir(os.path.join(base_path, "tas")):
            if not ta.endswith(".ta"):
                continue
            out[ta] = os.path.join(base_path, "tas", ta)
        return out
    else:
        print("TECNO; INFINIX unkown tee!", report_path, tee)
        exit(-24)


def get_filepath_oppo_vivo(report, tee):
    if tee == "kinibi":
        if not os.path.exists(report):
            return {}
        data = json.load(open(report))
        out = {}
        for ta in data:
            ta_name = ta["filename"].split("/")[-1]
            out[ta_name] = os.path.join(os.path.dirname(report), "tas", ta["filename"])
        return out
    elif tee == "qualcomm":
        out = {}
        if not os.path.exists(report):
            return {}
        data = json.load(open(report))
        base_path = os.path.dirname(report)
        for ta in data:
            ta_name = ta["ta_name"]
            found = find_qsee_ta(ta_name, os.path.join(base_path, "tas"))
            if found:
                out[ta_name] = found
        return out
    else:
        print("VIVO WITH BEANPOD, UNSUPPOTED!!!", report, tee)
        exit(-420)


def get_filepath_samsung(report, tee):
    out = {}
    if tee == "kinibi":
        if not os.path.exists(report):
            return {}
        data = json.load(open(report))
        for ta in data:
            filepath = ta["filename"]
            if not os.path.exists(filepath):
                #@TODO: add search into folders for the TA
                continue
            ta_name = filepath.split("/")[-1]
            out[ta_name] = filepath
        return out
    elif tee == "teegris" or tee == "mediatek_teegris":
        if not os.path.exists(report):
            return {}
        data = json.load(open(report))
        for ta in data:
            if 'sec_version' not in ta:
                continue
            name = get_teegris_name(ta["human_name"])
            if not os.path.exists(ta["filename"]):
                #@TODO: add search into folders for the TA
                continue
            out[name] = ta["filename"]
        return out
    elif tee == "qualcomm":
        if not os.path.exists(report):
            return {}
        data = json.load(open(report))
        base_path = os.path.dirname(report)
        version = base_path.split("/")[-1]
        for ta in data:
            ta_name = ta["ta_name"]
            found = find_qsee_ta(ta_name, os.path.join(base_path, version))
            if found:
                out[ta_name] = found
        return out
    else:
        print("UNKNWON TEE", report, tee)
        exit(42208)


def get_ta_filepath(report, tee, vendor):
    if vendor == "vivo" or vendor == "oppo":
        return get_filepath_oppo_vivo(report, tee)
    elif vendor == "xiaomi":
        return get_filepath_xiaomi(report, tee)
    elif vendor == "samsung":
        return get_filepath_samsung(report, tee)
    elif vendor == "infinix" or vendor == "tecno":
        return get_filepath_infinix_tecno(report, tee)
    else:
        print("Unknown VENDOR!!")
        exit(-4)
