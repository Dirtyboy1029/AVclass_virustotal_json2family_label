# -*- coding: utf-8 -*- 
# @Time : 2023/4/25 15:31 
# @Author : DirtyBoy 
# @File : vt2json.py

import requests
import json, pickle
import os, ast
import argparse


def json2txt(content, json_path):
    with open(json_path, 'w') as f:
        f.write(json.dumps(content))
    f.close()


def load_json(json_path):
    with open(json_path, 'r') as fp:
        data = json.load(fp)
    return data


def list_to_txt(goal, file_path):
    f = open(file_path, "w")
    for line in goal:
        f.write(line + '\n')
    f.close()


def txt_to_list(txt_path):
    f = open(txt_path, "r")
    return f.read().splitlines()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-year', '-y', type=str, default='2015')
    args = parser.parse_args()
    year = args.year
    API_ = txt_to_list('config/vt_keys.txt')  # your api
    headers = {
        'x-apikey': 'apikey',
        'Host': 'www.virustotal.com',
        'range': 'bytes=equest',
        'user-agent': 'curl/7.68.0',
        'accept': '*/*'
    }


    sha256_file = '/home/lhd/Android_malware_detector_set/malware_family_label/config/download_dataset_sha256/' + year + '_malware.txt'
    file_list = txt_to_list(sha256_file)
    #result_folder = 'json/last_analysis_results/' + year
    json_folder = 'json/vt_json/' + year
    #summary_folder = 'json/summary/' + year

    count = 0
    num_api = 3
    fail_sha256 = []
    for item in file_list:
        print('正在使用第' + str(num_api % len(API_) + 1) + '个apikey')
        headers['x-apikey'] = API_[num_api % len(API_)]
        file_sha256 = item
        url = "https://www.virustotal.com/api/v3/files/" + file_sha256 + ""
        res = requests.get(url=url, headers=headers)
        content = res.json()
        try:
            count += 1
            last_analysis_results = content['data']
            json2txt(content, os.path.join(json_folder, file_sha256 + '.json'))
            print(str(count) + '---' + file_sha256 + '解析完成')
        except KeyError:
            print(file_sha256 + '解析失败')
            num_api = num_api + 1
            fail_sha256.append(item)
    # list_to_txt(fail_sha256, 'fail_sha256_' + year + '.txt')
    fail_sha256_again = []
    print('将第一轮解析失败的file再次解析')
    for item in fail_sha256:
        file_sha256 = item
        url = "https://www.virustotal.com/api/v3/files/" + file_sha256 + ""
        content = requests.get(url=url, headers=headers)
        #content = res.json()
        try:
            count += 1
            last_analysis_results = content['data']
            json2txt(content, os.path.join(json_folder, file_sha256 + '.json'))
            print(str(count) + '---' + file_sha256 + '解析完成')
        except KeyError:
            print(file_sha256 + '解析失败')
            fail_sha256_again.append(file_sha256)
    if fail_sha256_again is not None:
        list_to_txt(fail_sha256_again, 'fail_again_json_sha256_' + year + '.txt')
