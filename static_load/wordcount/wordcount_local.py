from pyspark import SparkContext, SparkConf
import time

# 创建Spark配置对象
conf = SparkConf().setAppName("WordCount").setMaster("local")
# 创建SparkContext对象
sc = SparkContext(conf=conf)

# 定义函数来运行word count并返回运行时间
def run_word_count(file_path, run_number):
    # 计时器
    startTime = int(round(time.time() * 1000))

    # 读取数据
    data = sc.textFile(file_path)

    # 统计词频
    wordCounts = data.flatMap(lambda line: line.split(" ")) \
                     .filter(lambda word: word != "") \
                     .map(lambda word: (word, 1)) \
                     .reduceByKey(lambda a, b: a + b)

    # 存储数据
    output_dir = "file:///home/xzy/detection/static_load/wordcount/ wordcount{}".format(run_number)
    wordCounts.saveAsTextFile(output_dir)

    # 运行时间测试
    endTime = int(round(time.time() * 1000))
    return endTime - startTime

# 运行10次并计算平均运行时间
total_time = 0
for i in range(10):
    file_path = "file:///home/xzy/detection/static_load/wordcount/savedrecs.txt"
    runtime = run_word_count(file_path, i+1)  # 传入运行次数作为参数
    total_time += runtime
    print("第{}次运行时间：{}ms".format(i+1, runtime))

average_time = total_time / 10
print("平均运行时间：{}ms".format(average_time))

# 停止SparkContext
sc.stop()

