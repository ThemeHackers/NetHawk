import json
from tabulate import tabulate
import numpy as np
import sys
import configparser
import onnx
import tqdm
import time

from colorama import Fore, Style, init

init(autoreset=True)

util_path = "util"
sys.path.append(util_path)

from model_utils import check_and_download_models

def logo():
    print(rf'''
{Fore.CYAN}{Style.BRIGHT}  

                       __  ___        __    __  ____     ___                    __  _             
                      /  |/  /__  ___/ /__ / / /  _/__  / _/__  ______ _  ___ _/ /_(_)__  ___     
                     / /|_/ / _ \/ _  / -/) / _/ // _ \/ _/ _ \/ __/  ' \/ _ `/ __/ / _ \/ _ \    
                    /_/  /_/\___/\_,_/\__/_/ /___/_//_/_/ \___/_/ /_/_/_/\_,_/\__/_/\___/_//_/    
                                                                              

{Style.RESET_ALL}
        {Fore.GREEN}Author: ThemeHackers
        {Fore.GREEN}Github: https://github.com/ThemeHackers/NetHawk.git
        {Fore.GREEN}This code is the data inside the model.
{Style.RESET_ALL}
''')

def processing(total_steps=100):
    for step in tqdm.tqdm(range(total_steps), desc=Fore.CYAN + "Fetching data ...", unit="step"):
        time.sleep(0.1)

logo()
processing()

config = configparser.ConfigParser()
config.read('config.ini')

WEIGHT_PATH = config['Model']['WEIGHT_PATH']
MODEL_PATH = config['Model']['MODEL_PATH']
REMOTE_PATH = config['Model']['REMOTE_PATH']


onnx_to_numpy_dtype = {
    1: np.float32,   # ONNX.FLOAT
    2: np.float64,   # ONNX.DOUBLE
    3: np.int32,     # ONNX.INT32
    4: np.int64,     # ONNX.INT64
    5: np.uint8,     # ONNX.UINT8
    6: np.uint16,    # ONNX.UINT16
    7: np.uint32,    # ONNX.UINT32
    8: np.uint64,    # ONNX.UINT64
    9: np.int8,      # ONNX.INT8
    10: np.int16,    # ONNX.INT16
    11: np.bool_,    # ONNX.BOOL
    12: np.float16,  # ONNX.FLOAT16
 
}

def load_onnx_model(model_path):
    try:
        model = onnx.load(model_path)
        onnx.checker.check_model(model)
        return model
    except Exception as e:
        print(f"Error loading ONNX model: {e}")
        return None

def extract_model_info(model):
    info = {}
    info['opset_version'] = model.opset_import[0].version if model.opset_import else None

    metadata = model.metadata_props
    info['metadata'] = {prop.key: prop.value for prop in metadata}

    inputs = model.graph.input
    info['inputs'] = [
        {
            'name': inp.name,
            'shape': [
                dim.dim_value if dim.dim_value > 0 else "Dynamic" 
                for dim in inp.type.tensor_type.shape.dim
            ],
            'type': inp.type.tensor_type.elem_type
        }
        for inp in inputs
    ]

    outputs = model.graph.output
    info['outputs'] = [
        {
            'name': out.name,
            'shape': [
                dim.dim_value if dim.dim_value > 0 else "Dynamic" 
                for dim in out.type.tensor_type.shape.dim
            ],
            'type': out.type.tensor_type.elem_type
        }
        for out in outputs
    ]

    nodes = model.graph.node
    info['nodes'] = [{'name': node.name, 'op_type': node.op_type, 'inputs': node.input, 'outputs': node.output} for node in nodes]
    info['node_count'] = len(nodes)

    initializers = model.graph.initializer
    info['initializers'] = []
    total_param_count = 0

   
    for init in initializers:
        init_data_type = onnx_to_numpy_dtype.get(init.data_type, np.float32)  
        param_shape = init.dims
        param_count = np.prod(param_shape)
        total_param_count += param_count
        info['initializers'].append({
            'name': init.name,
            'shape': param_shape,
            'data_type': init_data_type.__name__,  
        })
    
    info['parameter_count'] = total_param_count
    
    info['memory_usage'] = sum(np.prod(init.dims) * np.dtype(onnx_to_numpy_dtype.get(init.data_type, np.float32)).itemsize for init in initializers)

    return info

def save_nodes_to_file(nodes, file_path="model.graph.node.json"):
    def serialize_node(node):
        return {
            'name': node['name'],
            'op_type': node['op_type'],
            'inputs': list(node['inputs']),  
            'outputs': list(node['outputs']) 
        }
    
    try:
        serializable_nodes = [serialize_node(node) for node in nodes]
        with open(file_path, "w") as f:
            json.dump(serializable_nodes, f, indent=4)
        print(f"\n=== Nodes saved to {file_path} ===")
    except Exception as e:
        print(f"Error saving nodes to file: {e}")

def display_model_info_as_table(info):
    print("\n=== Opset Version ===")
    print(f"Opset Version: {info['opset_version']}")
    time.sleep(3)
    print("\n=== Inputs ===")
    inputs_table = [
        [inp['name'], inp['shape'], inp['type']]
        for inp in info['inputs']
    ]
    print(tabulate(inputs_table, headers=["Name", "Shape", "Type"], tablefmt="grid"))
    time.sleep(3)
    print("\n=== Outputs ===")
    outputs_table = [
        [out['name'], out['shape'], out['type']]
        for out in info['outputs']
    ]
    print(tabulate(outputs_table, headers=["Name", "Shape", "Type"], tablefmt="grid"))
    time.sleep(3)
    print("\n=== Parameters ===")
    print(f"Total Parameters: {info['parameter_count']}")
    params_table = [
        [param['name'], param['shape'], param['data_type']]
        for param in info['initializers']
    ]
    print(tabulate(params_table, headers=["Name", "Shape", "Data Type"], tablefmt="grid"))

if __name__ == "__main__":
    check_and_download_models(WEIGHT_PATH, MODEL_PATH, REMOTE_PATH)
    model_path = "model.onnx"
    model = load_onnx_model(model_path)
    if model:
        model_info = extract_model_info(model)
        save_nodes_to_file(model_info['nodes'])
        display_model_info_as_table(model_info)
