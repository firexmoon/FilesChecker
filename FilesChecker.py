# coding=utf-8

import os
import sys
import hashlib
import json
import datetime
import hmac

hmac_key = b'firexmoon_FilesChecker_hmac_key_2018-9-21 22:05:54'
db_admin = 'libo'
db_file_name = 'files_checker.' + db_admin + '.db'
db_file_full_path = ''
read_buffer_size = 1024 * 512
main_dir_path = ''
print_to_file = True
print_file = sys.stdout

files_lose = []
files_change = []
files_new = []
files_failed = []

###
{
    'admin': db_admin,
    'db_ver': '2.0',
    'root': {
        'files': {
            'file_1': {
                'size': 1024,
                'sha256': '',
                'timestamp': ''
            }
        },
        'dirs': {
            'dir_1': {
                'files': {},
                'dirs': {}
            }
        }
    },
    'timestamp': '',
    'hmac': ''
}
###
files_info_db = {
    'admin': db_admin,
    'db_ver': '2.0',
    'root': {'files': {}, 'dirs': {}},
    'time_start': '',
    'time_finish': '',
    'hmac': ''
}


def is_ignore_file(file_full_path):
    if file_full_path.find(db_file_full_path) == 0:
        return True

    rel_path = os.path.relpath(file_full_path, main_dir_path)
    if rel_path == '.':
        return False
    else:
        rel_path_arr = rel_path.split(os.sep)
        for item in rel_path_arr:
            item = item.lower()
            if item[0] == '.' or item[0] == '@' or item[0] == '#':
                return True
            elif item[:2] == '__':
                return True
            elif item == 'thumbs.db':
                return True
            elif item.endswith('.tmp'):
                return True


def get_cur_time():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')


def compute_file_hash(filename):
    hash_sha256 = hashlib.sha256()
    with open(filename, 'rb') as fd:
        while 1:
            buf = fd.read(read_buffer_size)
            if not buf:
                break
            hash_sha256.update(buf)
    return hash_sha256.hexdigest()


def get_file_size(filename):
    size = os.path.getsize(filename)
    return "{:,}".format(size)


def enum_files_in_db_node(parent, node):
    files_list = []
    for file in node['files']:
        files_list.append(os.path.join(parent, file))
    for dir_name in node['dirs']:
        files_list.append(os.path.join(parent, dir_name))
        files_list.extend(
            enum_files_in_db_node(
                os.path.join(parent, dir_name),
                node['dirs'][dir_name])
        )
    return files_list


def get_dir_db_node(dir_path, create_new_node):
    rel_path = os.path.relpath(dir_path, main_dir_path)
    if rel_path == '.':
        return files_info_db['root']
    else:
        rel_path_arr = rel_path.split(os.sep)
        node = files_info_db['root']
        for d in rel_path_arr:
            if d not in node['dirs']:
                if create_new_node:
                    node['dirs'][d] = {'files': {}, 'dirs': {}}
                else:
                    return None
            node = node['dirs'][d]
        return node


def gen_file_info(file_full_path):
    file_rel_path = os.path.relpath(file_full_path, main_dir_path)
    
    # 获取文件大小
    try:
        file_size = get_file_size(file_full_path)
        print('\t\tsize: ' + file_size, file=print_file)
    except:
        print('\t\tget_file_size Failed!', file=print_file)
        files_failed.append(file_rel_path)
        return None

    # 计算文件Hash
    try:
        sha256 = compute_file_hash(file_full_path)
    except:
        print('\t\tcompute_file_hash Failed!', file=print_file)
        files_failed.append(file_rel_path)
        return None
    print('\t\tsha256: ' + sha256, file=print_file)

    return {'size': file_size, 'sha256': sha256}


def save_db_file():
    print(file=print_file)
    try:
        json_str = json.dumps(files_info_db, ensure_ascii=False, sort_keys=False)
        hmac_sha256 = hmac.new(hmac_key, json_str.encode(encoding='utf-8'), digestmod='SHA256')
        files_info_db['hmac'] = hmac_sha256.hexdigest()
        json.dump(files_info_db,
                  open(db_file_full_path, 'w', encoding='utf-8'),
                  ensure_ascii=False, sort_keys=False)
        print('Write DB file done.', file=print_file)
    except:
        print('Write DB file failed!', file=print_file)


def load_db_file():
    global files_info_db
    # 加载数据库
    try:
        files_info_db = json.load(open(db_file_full_path, 'r', encoding='utf-8'))
    except:
        print(file=print_file)
        print('!!!  Load DB file failed !!!', file=print_file)
        print(file=print_file)
        files_failed.append(db_file_name)
        return False

    # 检查hmac
    hmac_load = files_info_db['hmac']
    files_info_db['hmac'] = ''
    json_str = json.dumps(files_info_db, ensure_ascii=False, sort_keys=False)
    hmac_compute = hmac.new(hmac_key, json_str.encode(encoding='utf-8'), digestmod='SHA256').hexdigest()
    if not hmac.compare_digest(hmac_load, hmac_compute):
        print(file=print_file)
        print('!!! Verify DB file hmac failed !!!', file=print_file)
        print(file=print_file)
        files_failed.append(db_file_name)
        return False
    else:
        return True


def gen_files_info_db():
    global files_failed, files_info_db
    files_info_db['time_start'] = get_cur_time()

    for parent, dirs, files in os.walk(main_dir_path):
        if is_ignore_file(parent):
            continue

        print(file=print_file)
        print('now in dir: ' + os.path.relpath(parent, main_dir_path), file=print_file)
        parent_node = get_dir_db_node(parent, True)

        for file_name in files:
            file_full_path = os.path.join(parent, file_name)
            file_rel_path = os.path.relpath(file_full_path, main_dir_path)
            # 跳过忽略的文件
            if is_ignore_file(file_full_path):
                continue

            print('\tfile: ' + file_rel_path, file=print_file)

            file_info = gen_file_info(file_full_path)
            if not file_info:
                continue
            parent_node['files'][file_name] = file_info

    files_info_db['time_finish'] = get_cur_time()
    save_db_file()


def check_files(do_update):
    global files_info_db, files_lose, files_change, files_new, files_failed

    if not load_db_file():
        if do_update:
            gen_files_info_db()
        return

    print(file=print_file)
    print('--------------------------------------------------------', file=print_file)
    print(db_file_name, file=print_file)
    print('DB file hmac verify success.', file=print_file)
    print('DB version: ' + files_info_db['db_ver'], file=print_file)
    print('DB admin: ' + files_info_db['admin'], file=print_file)
    print('DB time_start: ' + files_info_db['time_start'], file=print_file)
    print('DB time_finish: ' + files_info_db['time_finish'], file=print_file)
    print('--------------------------------------------------------', file=print_file)

    files_info_db['time_start'] = get_cur_time()
        
    for parent, dirs, files in os.walk(main_dir_path):
        if is_ignore_file(parent):
            continue

        print(file=print_file)
        print('now in dir: ' + os.path.relpath(parent, main_dir_path), file=print_file)

        # 检查当前目录是否在DB中
        parent_node = get_dir_db_node(parent, False)
        if not parent_node:
            files_new.append(os.path.relpath(parent, main_dir_path))
            print('\tNew dir.', file=print_file)
            if do_update:
                parent_node = get_dir_db_node(parent, True)
            for file_name in files:
                file_full_path = os.path.join(parent, file_name)
                file_rel_path = os.path.relpath(file_full_path, main_dir_path)
                if is_ignore_file(file_full_path):
                    continue

                print('\tfile: ' + file_rel_path, file=print_file)
                files_new.append(file_rel_path)
                if do_update:
                    file_info = gen_file_info(file_full_path)
                    if not file_info:
                        continue
                    parent_node['files'][file_name] = file_info
            continue

        # 查找当前目录下缺失的目录
        for dir_name in list(parent_node['dirs']):
            if dir_name not in dirs:
                dir_full_path = os.path.join(parent, dir_name)
                dir_rel_path = os.path.relpath(dir_full_path, main_dir_path)
                print('\tLose dir: ' + dir_rel_path, file=print_file)
                files_lose.append(dir_rel_path)
                files_lose.extend(
                    enum_files_in_db_node(dir_rel_path, parent_node['dirs'][dir_name])
                )
                if do_update:
                    del parent_node['dirs'][dir_name]

        # 查找当前目录下缺失的文件
        for file_name in list(parent_node['files']):
            if file_name not in files:
                file_full_path = os.path.join(parent, file_name)
                file_rel_path = os.path.relpath(file_full_path, main_dir_path)
                print('\tLose file: ' + file_rel_path, file=print_file)
                files_lose.append(file_rel_path)
                if do_update:
                    del parent_node['files'][file_name]

        for file_name in files:
            file_full_path = os.path.join(parent, file_name)
            file_rel_path = os.path.relpath(file_full_path, main_dir_path)

            # 跳过忽略的文件
            if is_ignore_file(file_full_path):
                continue
            print('\tfile: ' + file_rel_path, file=print_file)

            if file_name not in parent_node['files']:
                files_new.append(file_rel_path)
                print('\t\tNew file.', file=print_file)
                if do_update:
                    file_info = gen_file_info(file_full_path)
                    if not file_info:
                        continue
                    parent_node['files'][file_name] = file_info
                continue

            else:
                file_info = parent_node['files'][file_name]

                # 获取文件大小
                size_different = False
                try:
                    file_size = get_file_size(file_full_path)
                    if file_size != file_info['size']:
                        size_different = True
                        files_change.append(file_rel_path)
                        print('\t\tsize: ' + file_size + ', Different!', file=print_file)
                        if do_update:
                            file_info['size'] = file_size
                        else:
                            continue
                except:
                    print('\t\tget_file_size Failed!', file=print_file)
                    files_failed.append(file_rel_path)
                    continue

                # 计算文件Hash
                try:
                    sha256 = compute_file_hash(file_full_path)
                    if not hmac.compare_digest(sha256, file_info['sha256']):
                        if not size_different:
                            files_change.append(file_rel_path)
                        print('\t\tsha256: ' + sha256 + ', Different!', file=print_file)
                        if do_update:
                            file_info['sha256'] = sha256
                        continue
                except:
                    print('\t\tcompute_file_hash Failed!', file=print_file)
                    files_failed.append(file_rel_path)
                    continue

                # print('\t\tIdentical.', file=print_file)

    files_info_db['time_finish'] = get_cur_time()
    
    if do_update:
        save_db_file()


def do_summary():
    print(file=print_file)
    print('----------------------------', file=print_file)
    if len(files_lose) > 0:
        print('lose:', file=print_file)
        for f in files_lose:
            print('\t' + f, file=print_file)
    if len(files_change) > 0:
        print('change:', file=print_file)
        for f in files_change:
            print('\t' + f, file=print_file)
    if len(files_new) > 0:
        print('new:', file=print_file)
        for f in files_new:
            print('\t' + f, file=print_file)
    if len(files_failed) > 0:
        print('failed:', file=print_file)
        for f in files_failed:
            print('\t' + f, file=print_file)

    print(file=print_file)
    print('All done.', file=print_file)

    if files_info_db['time_start'] != '':
        t1 = datetime.datetime.strptime(files_info_db['time_start'], '%Y-%m-%d %H:%M:%S.%f')
        t2 = datetime.datetime.strptime(files_info_db['time_finish'], '%Y-%m-%d %H:%M:%S.%f')
        delta = t2 - t1
        print('eclipse ' +
              (datetime.datetime.strptime('0:0:0', '%H:%M:%S') + delta).strftime('%H:%M:%S.%f'),
              file=print_file)

    print('----------------------------', file=print_file)


if __name__ == '__main__':
    actParam = '-u'
    if len(sys.argv) == 1:
        print('缺少参数，结束运行。')
        sys.exit()
    elif len(sys.argv) == 2:
        main_dir_path = sys.argv[1]
    elif len(sys.argv) == 3:
        actParam = sys.argv[1]
        main_dir_path = sys.argv[2]
    else:
        print('参数过多，结束运行。')
        sys.exit()

    main_dir_path = os.path.normcase(main_dir_path)
    if os.path.basename(main_dir_path) == '':
        main_dir_path = os.path.dirname(main_dir_path)
    if not os.path.exists(main_dir_path):
        print('无效的参数，结束运行。')
        sys.exit()

    # db_file_full_path = os.path.join(main_dir_path, db_file_name)
    db_file_full_path = '/report/' + db_file_name
    
    if print_to_file:
        print_file_name = db_file_name + '.report.' \
                          + datetime.datetime.now().strftime('%Y-%m-%d %H%M%S') + '.txt'
        print_file = open('/report/' + print_file_name, 'w', encoding='utf-8')

    if actParam == '-g':
        gen_files_info_db()

    elif actParam == '-c':
        check_files(False)

    elif actParam == '-u':
        check_files(True)

    else:
        print('无效参数，结束运行。')
        sys.exit()

    do_summary()
    if print_to_file:
        print_file.close()
