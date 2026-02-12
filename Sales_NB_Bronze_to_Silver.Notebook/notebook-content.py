# Fabric notebook source

# METADATA ********************

# META {
# META   "kernel_info": {
# META     "name": "synapse_pyspark"
# META   },
# META   "dependencies": {}
# META }

# CELL ********************

# MAGIC %%configure
# MAGIC {
# MAGIC   "defaultLakehouse": {
# MAGIC     "name": { "parameterName": "lakehouse_name", "defaultValue": "Sales_LH" },
# MAGIC     "id": { "parameterName": "lakehouse_id", "defaultValue": "de90dbe0-5fbe-478d-8db5-5dde67bc1cd6" },
# MAGIC     "workspaceId": { "parameterName": "workspace_id", "defaultValue": "35196c76-930f-406e-b6c8-5293ea0531d2" },
# MAGIC   }
# MAGIC }


# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# CELL ********************

bronze_sales_df = spark.sql("SELECT * FROM dbo.bronze_sales")
display(bronze_sales_df)

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# CELL ********************

from pyspark.sql.functions import col
from pyspark.sql.types import IntegerType, DoubleType, DateType

silver_sales_df = bronze_sales_df.select(
    col("SalesOrderNumber").alias("SalesOrderNumber"),
    col("SalesOrderLineNumber").cast(IntegerType()).alias("SalesOrderLineNumber"),
    col("OrderDate").cast(DateType()).alias("OrderDate"),
    col("CustomerName").alias("CustomerName"), 
    col("EmailAddress").alias("EmailAddress"), 
    col("Item").alias("Item"),                
    col("Quantity").cast(IntegerType()).alias("Quantity"),
    col("UnitPrice").cast(DoubleType()).alias("UnitPrice"),
    col("TaxAmount").cast(DoubleType()).alias("TaxAmount")
)

display(silver_sales_df)

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# CELL ********************

silver_sales_df.write.mode("overwrite").saveAsTable("dbo.silver_sales")

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }

# CELL ********************

vl = notebookutils.variableLibrary.getLibrary("Sales_VL")

workspace_name = vl.getVariable("workspace_name")
lakehouse_name = vl.getVariable("lakehouse_name")

silver_sales_df = spark.read.format("delta").load(f"abfss://{workspace_name}@onelake.dfs.fabric.microsoft.com/{lakehouse_name}.Lakehouse/Tables/dbo/silver_sales")

display(silver_sales_df)

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "synapse_pyspark"
# META }
