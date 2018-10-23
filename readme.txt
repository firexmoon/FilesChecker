2018-09-27 09:32

运行环境：Python 3.6.5

功能介绍：用jsonDB存储指定目录下的所有文件数据版本（size，sha-256），以报告形式输出该目录当前所有文件数据与jsonDB中记录的版本的差异（增删该），并更新jsonDB数据与当前文件数据版本保持一致，供下次检查使用。jsonDB具有HMAC保护数据完整性。

使用方法：python FilesChecker.py C:\main_dir

-g 开关，仅产生jsonDB；
-c 开关，仅依据jsonDB生成检查报告，不更新jsonDB；
-u 开关（默认），如果还没有jsonDB，生成jsonDB；如果已经有jsonDB；生成检查报告并更新jsonDB；

设置 print_to_file 开关，将检查报告以文件形式保存在目标目录下；否则将报告输出在终端上；
设置 hmac_key 更新HMAC密钥；
设置 db_admin 标识HMAC管理员；
在is_ignore_file()函数中设置要排除的文件名、目录名。


