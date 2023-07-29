import pandas as pd

def search_url(url):
    # 設定CSV檔案的路徑和要讀取的欄位名稱
    csv_file_path = 'online-valid.csv'
    desired_column = 'url'

    df = pd.read_csv(csv_file_path, usecols=[desired_column])

    filtered_data =  df[df[desired_column]==url]
    if filtered_data.empty:
        return False
    else:
        return True

