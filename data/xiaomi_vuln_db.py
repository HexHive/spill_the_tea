VULNS = {
    # Qualcomm
    #"soter64" : [("12/2021", "6/2022")],
    # mediatek
    "d78d338b1ac349e09f65f4efe179739d" : [("7/2020","12/2020","None", "scanner", "param_confusion"), ("12/2021","2/2022","CVE-2020-14125","public", "heap_overflow")], 
    "08030000000000000000000000000000" : [("12/2020","10/2023","CVE-2023-32834","public", "param_confusion")],
    "08110000000000000000000000000000" : [("12/2020","10/2023","CVE-2023-32835", "public", "param_confusion")],
    "08020000000000000000000000007169" : [("12/2020","10/2023","MSV-828", "public", "param_confusion")],
    "09030000000000000000000000008270" : [("12/2020","10/2023","CVE-2023-32848","public", "param_confusion")],
    "09010000000000000000000000000000" : [("12/2020","10/2023","CVE-2023-32849","public", "param_confusion")],
    "98fb95bcb4bf42d26473eae48690d7ea" : [("12/2020","5/2023","CVE-2023-20722","public", "param_confusion")],
    "14498ace2a8f11e880c8509a4c146f4c" : [("7/2020","4/2021","None","scanner", "param_confusion")],
    "08010203000000000000000000000000" : [("7/2020","4/2021","None","scanner", "param_confusion")]
}

# very not sure about this
MEDIATEKTA2NAME = {
    "14498ace2a8f11e880c8509a4c146f4c" : "fido", # fido_ta in path to c file,
    "3d08821c33a611e6a1fa089e01c83aa2" : "vsimapp",
    "86f623f6a2994dfdb560ffd3e5a62c29" : "widevine",
    "c09c9c5daa504b78b0e46eda61556c3a" : "keymaster",
    "c1882f2d885e4e13a8c8e2622461b2fa" : "gatekeeper", 
    "d78d338b1ac349e09f65f4efe179739d" : "soter",
    "d91f322ad5a441d5955110eda3272fc0" : "key_manager",
    "e5140b3376fa4c63ab18062caab2fb5c" : "secauth",
    "08010203000000000000000000000000" : "alipay",
    "98fb95bcb4bf42d26473eae48690d7ea" : "ta_m4u",
    "9073f03a9618383bb1856eb3f990babd" : "m4u2?",
    #"08050000000000000000000000003419" : "pmem", driver?
    "e97c270ea5c44c58bcd3384a2fa2539e" : "wvl1",
    "4be4fd221f2c11e5b5f7727283247c7f" : "decoder?",
    "7778c03fc30c4dd0a319ea29643d4d4b" : "fpc",
    # "020f0000000000000000000000000000" : "smem" driver?
    "08070000000000000000000000008270" : "vp9",
    "655a4b46cd7711eaaafbf382a6988e7b" : "otrapp",
    #"020b0000000000000000000000000000" : "drv_cmdq", driver?
    "08020000000000000000000000007169" : "ta_decoder",
    "8888c03fc30c4dd0a319ea29643d4d4b" : "gf",
    "07060000000000000000000000007169" : "avc_drv",
    "06090000000000000000000000000000" : "ki_drv",
    "08030000000000000000000000000000" : "ta_secmem",
    "08110000000000000000000000000000" : "ta_keyinstall",
    "40188311faf343488db888ad39496f9a" : "drv_wvl1",
    "09030000000000000000000000008270" : "ta_decoder2",
    "09010000000000000000000000000000" : "ta_cmdq",
    #"93feffccd8ca11e796c7c7a21acb4932" : "spio_drv"
}