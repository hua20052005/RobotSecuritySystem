from sklearn.ensemble import IsolationForest

def run_anomaly_detection(df, contamination=0.01):
    """
    contamination: 预估的异常比例，0.01 代表假设有 1% 的包是异常的
    """
    # 选择特征列进行训练
    features = ['size', 'interval', 'port']
    X = df[features]

    print("[*] 正在启动孤立森林算法进行无监督分析...")
    model = IsolationForest(contamination=contamination, random_state=42)
    
    # 预测：1 为正常，-1 为异常
    df['anomaly_label'] = model.fit_predict(X)
    
    # 提取异常包
    anomalies = df[df['anomaly_label'] == -1].copy()
    return df, anomalies