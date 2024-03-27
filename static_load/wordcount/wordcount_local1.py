from pyspark import SparkContext, SparkConf

# 创建Spark配置对象
conf = SparkConf().setAppName("WordCount").setMaster("local")
# 创建SparkContext对象
sc = SparkContext(conf=conf)

# 计时器
startTime = int(round(time.time() * 1000))

# 读取数据
data = sc.textFile("file:///home/xzy/detection/static_load/wordcount/savedrecs.txt")

# 统计词频
wordCounts = data.flatMap(lambda line: line.split(" ")) \
                 .filter(lambda word: word != "") \
                 .map(lambda word: (word, 1)) \
                 .reduceByKey(lambda a, b: a + b)

# 给词频排序并输出
topWordCounts = wordCounts.map(lambda x: (x[1], x[0])).sortByKey(False)
top5Words = topWordCounts.take(5)
for word in top5Words:
    print(word)

# 存储数据
wordCounts.saveAsTextFile("file:///home/xzy/detection/static_load/wordcount/wordcount1")

# 运行时间测试
endTime = int(round(time.time() * 1000))
print("程序运行时间： " + str(endTime - startTime) + "ms")

# 停止SparkContext
sc.stop()
