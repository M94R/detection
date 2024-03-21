from pyspark.sql import SparkSession
import time

# 创建 SparkSession
spark = SparkSession.builder \
    .appName("Calculate Pi") \
    .getOrCreate()

# 设置重复次数
repeat_times = 10
times = []

for i in range(repeat_times):
    start_time = time.time()
    
    # 计算 Pi
    n = 1000000
    count = spark.sparkContext.parallelize(range(1, n+1)) \
        .map(lambda x: (x, 1) if x <= 1 or x**2 % 2 == 1 else (x, 0)) \
        .map(lambda x: x[1]) \
        .reduce(lambda x, y: x + y)

    pi_value = 4.0 * count / n

    end_time = time.time()
    execution_time = end_time - start_time
    times.append(execution_time)
    
    print(f"Iteration {i+1}: Pi is approximately {pi_value}, Execution time: {execution_time} seconds")

# 求平均时间
average_time = sum(times) / len(times)
print(f"Average execution time over {repeat_times} iterations: {average_time} seconds")

# 停止 SparkSession
spark.stop()

