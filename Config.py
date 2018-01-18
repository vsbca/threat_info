
import configparser

VT_API = ""
CYMON_API =""

def confReader(conf_file_path="./", file_name="secret.conf"):
    config = configparser.ConfigParser()
    
    config.read(conf_file_path+file_name)
    conf_dict={}

    for key in config['secrets']:
        conf_dict[key] = config['secrets'][key]
        
    return conf_dict


def initsettings():
    global VT_API,CYMON_API
    conf = confReader(conf_file_path="./", file_name="secret.conf")
    CYMON_API = conf['cymon_api']
    VT_API = conf['vt_api']

if __name__ == '__main__':
    print(confReader())

