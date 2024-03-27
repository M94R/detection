import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.datasets import load_iris #调用数据
from scipy.spatial.distance import cdist #导入了 SciPy 库中的距离计算函数 cdist，用于计算数据点之间的距离
import time

iris = load_iris() #导入sklearn自带的鸢尾花数据集
X = pd.DataFrame(iris.data, columns=iris.feature_names)
# print(X.head(10))

#取其中两个维度，绘制原始数据散点分布图
#x, y为散点坐标，c是散点颜色，marker是散点样式（如'o'为实心圆）
# plt.scatter(X["sepal length (cm)"], X["sepal width (cm)"], 
# c = "red", marker='o', label='sample')
# #横坐标轴标签
# plt.xlabel('sepal length')
# #纵坐标轴标签
# plt.ylabel('sepal width')
# #plt.legend设置图例的位置
# plt.legend(loc=2)
# # plt.show()


#寻找最佳的k值，即聚类个数
#聚类的目标是使得每个样本点到距离其最近的聚类中心的总误差平方和（也即聚类的代价函数，记作SSE）尽可能小
#先对图像样式做一些设计
# plt.plot()
# colors = ['b','g','r']  
# markers = ['o','v','s']  
#  #生成一个字典保存每次的代价函数
# distortions = []
# K = range(1,10)
# for k in K:
#     #分别构建各种K值下的聚类器
#     Model = KMeans(n_clusters=k).fit(X) 
#     #计算各个样本到其所在簇类中心欧式距离(保存到各簇类中心的距离的最小值)
#     distortions.append(sum(np.min(cdist(X, Model.cluster_centers_, 'euclidean'), axis=1)) / X.shape[0])

#绘制各个K值对应的簇内平方总和，即代价函数SSE
#可以看出当K=3时，出现了“肘部”，即最佳的K值。
# plt.plot(K,distortions,'bx-')
# #设置坐标名称
# plt.xlabel('optimal K')
# plt.ylabel('SSE')
# plt.show()

# 寻找最佳的k值，即聚类个数
distortions = []
K = range(1, 10)
best_time = float('inf')
best_k = None
for k in K:
    start_time = time.time()  # 记录开始时间
    total_time = 0  # 初始化总时间为0

#     model = KMeans(n_clusters=k)
#     model.fit(X)
#     end_time = time.time()
#     elapsed_time = end_time - start_time

#     if elapsed_time < best_time:
#         best_time = elapsed_time
#         best_k = k

#     print(f"K={k} 完成，运行时间: {elapsed_time} 秒")

# print(f"最佳聚类数量: K={best_k}, 最终迭代运行时间: {best_time} 秒")
    # 运行KMeans算法10次并计算平均运行时间
    num_iterations = 10
    for i in range(num_iterations):  # 运行10次
        model = KMeans(n_clusters=k)
        model.fit(X)
        end_time = time.time()
        elapsed_time = end_time - start_time
        total_time += elapsed_time  # 累加每次运行的时间

        print(f"Iteration {i+1}: Time taken - {elapsed_time} seconds")


average_time = total_time / 10  # 计算平均运行时间
print(f"K={k}, 平均运行时间: {average_time} 秒")
distortions.append(model.inertia_)

# 显示迭代过程
def plot_kmeans_iteration(X, centroids_history):
    for centroids in centroids_history:
        plt.scatter(X[:, 0], X[:, 1], c=model.labels_, cmap='viridis', alpha=0.5)
        plt.scatter(centroids[:, 0], centroids[:, 1], c='red', marker='x')
        plt.xlabel('sepal length')
        plt.ylabel('sepal width')
        plt.title('K-Means Clustering Iteration')
        plt.show()

# 迭代过程
def kmeans_iteration(X, n_clusters, max_iter=10):
    centroids_history = []
    model = KMeans(n_clusters=n_clusters)
    model.fit(X)
    centroids_history.append(model.cluster_centers_.copy())

    for _ in range(max_iter):
        model.fit(X)
        centroids_history.append(model.cluster_centers_.copy())

    return centroids_history

# 进行迭代
centroids_history = kmeans_iteration(X.values[:, :2], n_clusters=3, max_iter=5)
plot_kmeans_iteration(X.values[:, :2], centroids_history)

# #建模
# model = KMeans(n_clusters=3) #构造聚类器
# model.fit(X) #拟合我们的聚类模型
# label_pred = model.labels_ #获取聚类标签
# #类型不同需要转化
# # print("聚类标签：" + str(label_pred))
# # print(f"聚类标签：{label_pred}")

# ctr = model.cluster_centers_  #获取聚类中心,k=3,也就是3个中心
# # print(f"聚类中心为：{ctr}")

# inertia = model.inertia_ #获取SSE
# # print("计算得到聚类平方误差总和为",inertia)

# #绘制K-Means结果
# #取出每个簇的样本
# x0 = X[label_pred == 0]
# x1 = X[label_pred == 1]
# x2 = X[label_pred == 2]
# #分别绘出各个簇的样本
# plt.scatter(x0["sepal length (cm)"], x0["sepal width (cm)"], 
#             c = "red", marker='o', label='label0')
# plt.scatter(x1["sepal length (cm)"], x1["sepal width (cm)"], 
#             c = "green", marker='*', label='label1')
# plt.scatter(x2["sepal length (cm)"], x2["sepal width (cm)"], 
#             c = "blue", marker='+', label='label2')
# plt.scatter(model.cluster_centers_[:,0],model.cluster_centers_[:,1],
#             c = "black", marker='s',label='centroids')
# plt.xlabel('sepal length')
# plt.ylabel('sepal width')
# plt.legend(loc=2)
# plt.show()
