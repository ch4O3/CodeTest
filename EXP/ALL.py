import sys,importlib,glob,os,datetime
sys.path.append('../')
#from concurrent.futures import ThreadPoolExecutor,wait,as_completed,ALL_COMPLETED
from ClassCongregation import color

vuln_scripts = []
exp_scripts = []
for _ in glob.glob('EXP/*.py'):
    script_name = os.path.basename(_).replace('.py', '')
    if script_name != 'ALL' and script_name != '__init__':
        vuln_name = importlib.import_module('.%s'%script_name,package='EXP')
        exp_scripts.append(script_name)
        vuln_scripts.append(vuln_name)

def check(**kwargs):
    result = ''
    now = datetime.datetime.now()
    color ("["+str(now)[11:19]+"] " + "[+] Scanning target domain "+kwargs['url'], 'green')
    #批量调用
    for index in range(len(vuln_scripts)):
        try:
            result += vuln_scripts[index].check(**kwargs)+'\n'
        except Exception as e:
            now = datetime.datetime.now()
            color ("["+str(now)[11:19]+"] " + "[-] Running {} occured error!!!".format(exp_scripts[index]), 'yellow')
            continue
    return result
    #executor = ThreadPoolExecutor(max_workers = 3)
    #for data in executor.map(lambda kwargs: check(**kwargs),vuln_scripts):
    #    pass