import angr
import os
from pathlib import Path

def extract_cfg(apk_path:str, sensitive_apis : list[str]):
    """

    :param apk_path: absolute Path to the .apk file
    :param sensitive_apis: the list of android sensitive apis
    :return:
    """
    path_object = Path(apk_path)
    if not path_object.exists() or path_object.suffix != ".apk":
        raise FileNotFoundError

    print(f"[*] Extracting {path_object.name} into angr ....")
    loading_opts = {"android_sdk": "/Users/calebdeji/Library/Android/sdk/"}
    project = angr.Project(path_object, main_opts=loading_opts, auto_load_libs=False)

    print(f"[*] Done extracting {path_object.name} into angr ....")

    sensitive_api_addresses = {}
    for sensitive_api in sensitive_apis:
        symbol = project.loader.find_symbol(sensitive_api)
        if symbol :
            sensitive_api_addresses[sensitive_api] = symbol.rebased_addr
        else:
            print(f"[!] {path_object.name} doesn't have {sensitive_api} ...")
    if not sensitive_api_addresses:
        print(f"[!] No sensitive apis found in {path_object.name}. Existing")
        return

    print(f"[*] Extracting {path_object.name} CFG.")
    cfg = project.analyses.CFGEmulated(keep_state=True, state_add_options=angr.options.refs, context_sensitivity_level=2)

    print("[*] Identifying call sites for sensitive apis...")

    for api_name, api_address in sensitive_api_addresses.items():
        api_func_nodes = cfg.model.get_all_nodes(api_address)

        if not api_func_nodes:
            print(f"[-] No noeds in CFG for {api_name} ... Might be a dead code")
            continue

        calling_nodes = []
        for node in api_func_nodes:
            calling_nodes.extend(node.predecessors)

        if not calling_nodes:
            print(f"[-] no calling nodes for {api_name} were found in the CFG")
            continue

        for index, call_site_node in enumerate(calling_nodes):
            print(f"[*] Analyzing call site #{index+1} at {hex(call_site_node.addr)}")
            slicing_criterion = (call_site_node.addr, -1)

            backward_slicing = project.analyses.BackwardSlicing(cfg, cdg = None, ddg = None, targets = slicing_criterion)

            forward_slicing = project.analyses.ForwardSlicing(cfg, targets = slicing_criterion)

            print(f"[*] Backward slicing contains {len(backward_slicing.backward_slice)} blocks")
            print(f"[*] Forward slicing contains {len(forward_slicing.forward_slice)} blocks")

            #Full slice?

if __name__ == "__main__":
    apk_path = os.path.join("sample.apk")
    SENSITIVE_APIS_TO_FIND = [
        "Landroid/telephony/SmsManager;->sendTextMessage",
        "Landroid/telephony/TelephonyManager;->getDeviceId",
        "Landroid/location/LocationManager;->getLastKnownLocation",
        "Ljava/lang/Runtime;->exec"
    ]

    extract_cfg(apk_path, SENSITIVE_APIS_TO_FIND)
    # try:
    # except Exception as e:
    #     print(f"[!] An error occurred: {e}")
