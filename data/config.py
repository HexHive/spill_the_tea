fw_path = "/fw"

samsung_mtk = ["SM-A225F", "SM-A326B"]


devices = {
    "xiaomi":{
        "dandelion": "mediatek",
        "fleur": "mediatek",
        "rosemary": "mediatek",
        "cannong": "mediatek",
        "mojito": "qualcomm",
        "apollo": "qualcomm",
        "dipper": "qualcomm",
        "veux": "qualcomm",
        "spes": "qualcomm"
    },
    "samsung":{
        "SM-G920F": "kinibi",
        "SM-G920A": "kinibi",
        "SM-G930F": "kinibi",
        "SM-G950F": "kinibi",
        "SM-G960F": "kinibi",
        "SM-A530F": "kinibi",
        "SM-G973F": "teegris",
        "SM-G980F": "teegris",
        "SM-A105F": "teegris",
        "SM-A105G": "teegris",
        "SM-A102U1": "teegris",
        "SM-A405FN": "teegris",
        "SM-A225F": "mediatek_teegris",
        "SM-A326B": "mediatek_teegris",
        "SM-G991B": "teegris",
        "SM-S901B": "teegris",
        "SM-G9300": "qualcomm",
        "SM-G9500": "qualcomm",
        "SM-G9730": "qualcomm",
        "SM-G981U": "qualcomm",
        "SM-A9200": "qualcomm",
        "SM-G991U1": "qualcomm"
    },
    "oppo":{
        "reno3_pro": "kinibi",
        "reno4_pro": "qualcomm",
        "a92": "qualcomm",
        "a16k": "kinibi",
        "a73": "kinibi",
        "find_x3_pro": "qualcomm",
        "a16s": "kinibi",
        "f7_youth": "kinibi",
        "a5": "qualcomm",
        #"a17k": "kinibi",
        #"reno8_pro": "kinibi"
    },
    "vivo":{
        "z1x": "qualcomm",
        "y20g": "kinibi",
        "y33s": "kinibi",
        "y21": "kinibi",
        "y73": "kinibi",
        "x60_pro": "qualcomm",
        "y20": "qualcomm",
        #"y27": "kinibi"
    },
    "infinix": {
    },
    "tecno": {
        "camon_isky2": "mediatek",
        "camon_iace2x": "mediatek",
        "camon_18p": "mediatek",
        "camon_15p": "mediatek",
        #"pova5pro": "kinibi",
        #"camon_18p_kb": "kinibi"
    }
}

other_vendors = {
    "oppo" : {
        "reno_5g" : {
            "version": "?",
            "date": "2/2021",
            "tee" : "QSEE"
        },
        "reno_6" : {
            "version" : "?",
            "date" : "5/2022",
            "tee" : "QSEE"
        },
        "find_x3" : {
            "version" : "?",
            "date" : "4/2022",
            "tee" : "QSEE"
        },
        "reno_8" : {
            "version" : "?",
            "date" : "11/2022",
            "tee" : "QSEE"
        }
    },
    "vivo" : {
        "v17" : {
            "version" : "PD1948F_EX_A_8.75.20",
            "date" : "12/2021",
            "tee" : "QSEE"
        },
        "v19" : {
            "version" : "PD1969F_EX_A_6.72.8",
            "date" : "10/2022",
            "tee" : "QSEE"
        },
        "s1_pro" : {
            "version" : "PD1945F_EX_A_9.78.14",
            "date" : "10/2022",
            "tee" : "QSEE"
        },
        "v20_se" : {
            "version" : "PD2038F_EX_A_8.79.22",
            "date" : "10/2022",
            "tee" : "QSEE"
        },
        "y50" : {
            "version" : "PD1965F_EX_A_1.70.26",
            "date" : "6/2022",
            "tee" : "QSEE"
        }
    },
    "oneplus" : {
        "oneplus_9" : {
            "version" : "11.2.10.10.LE25BA",
            "date" : "1/2022",
            "tee" : "QSEE"
        },
        "oneplus_8T" : {
            "version" : "11.0.12.12.KB05DA",
            "date" : "3/2022",
            "tee" : "QSEE"
        },
        "oneplus_7" : {
            "version" : "11.0.9.1.GM57AA",
            "date" : "8/2022",
            "tee": "QSEE"
        },
        "oneplus_6" : {
            "version" : "11.1.2.2",
            "date" : "11/2022",
            "tee" : "QSEE"
        }
    },
    "lg" : {
        "v30" : {
            "version": "VS99630D_02",
            "date" : "8/2022",
            "tee" : "QSEE"
        },
        "v40" : {
            "version" : "V40EB30D_00",
            "date" : "3/2023",
            "tee" : "QSEE"
        }
    },
    "huawei" : {
        "p50_pro" : {
            "version" : "C432E1R5P1",
            "date" : "3/2022",
            "tee" : "QSEE"
        },
        "mate_50_pro" : {
            "version" : "103.0.0.126_C10E10R2P1",
            "date" : "9/2022",
            "tee" : "QSEE"
        },
        "nova_9_SE" : {
            "version" : "JLN-AL00_102.0.1.125_SP3C00E120R2P2",
            "date" : "3/2022",
            "tee" : "QSEE"
        },
        "y90" : {
            "version" : "C185E3R1P2",
            "date" : "8/2022",
            "tee" : "QSEE"
        }
    }
}
