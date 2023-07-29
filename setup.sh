#!/bin/sh

sudo apt install python3 python3-pip python3-flask -y

pip install -r requirements.txt 

# 指定要檢查的檔案名稱
target_file="online-valid.csv"

# 檢查目錄下是否有指定的檔案
if [ -e "$target_file" ]; then
    echo "File '$target_file' found in the directory."
else
    # 如果檔案不存在，則執行指令（這裡使用 echo 做示範）
    echo "File '$target_file' not found. Running the command..."
    # 在這裡替換您想要執行的指令
    wget http://data.phishtank.com/data/online-valid.csv
fi

if [ -e "templates" ]; then
    echo "Directory templates found in the directory."
else
    # 如果檔案不存在，則執行指令（這裡使用 echo 做示範）
    echo "Directory templates not found. Running the command..."
    # 在這裡替換您想要執行的指令
    mkdir templates
fi

flask run --host=0.0.0.0
