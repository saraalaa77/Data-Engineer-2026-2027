SELECT DISTINCT label
INTO Dim_Label
FROM [dbo].[cleaned_data_v1 - cleaned_cic_ids2017];
GO
use [CICIDS2017 Database];
select * from Dim_Label

ALTER TABLE Dim_Label
ADD Label_ID INT IDENTITY(1,1);

GO

ALTER TABLE Dim_Label
ADD CONSTRAINT PK_Dim_Label
PRIMARY KEY (Label_ID);

GO
SELECT * FROM Dim_Label;
GO
USE [CICIDS2017 Database];
SELECT
    IDENTITY(BIGINT, 1, 1) AS Flow_ID,
    t.timestamp,
    t.destination_port,
    t.flow_duration,
    t.total_fwd_packets,
    t.total_backward_packets,
    d.Label_ID
INTO [dbo].[Fact_Network_Flows]
FROM [dbo].[cleaned_data_v1 - cleaned_cic_ids2017] t
JOIN [dbo].[Dim_Label] d
    ON t.label = d.label;


GO










ALTER TABLE Fact_Network_Flows
ADD CONSTRAINT PK_Fact_Network_Flows
PRIMARY KEY (Flow_ID);


ALTER TABLE Fact_Network_Flows
ADD CONSTRAINT FK_Fact_Label
FOREIGN KEY (Label_ID)
REFERENCES Dim_Label(Label_ID);

























USE [CICIDS2017 Database];
GO

-- Create Fact Table with all features
SELECT
    IDENTITY(BIGINT, 1, 1) AS Flow_ID,
    t.*,
    d.Label_ID
INTO dbo.Fact_Network_Flows
FROM dbo.[cleaned_data_v1 - cleaned_cic_ids2017] t
JOIN dbo.Dim_Label d
    ON t.label = d.label;
GO

-- Remove original label column
ALTER TABLE dbo.Fact_Network_Flows
DROP COLUMN label;
GO

-- Add Foreign Key
ALTER TABLE dbo.Fact_Network_Flows
ADD CONSTRAINT FK_Fact_Label
FOREIGN KEY (Label_ID)
REFERENCES dbo.Dim_Label(Label_ID);
GO
SELECT COUNT(*) AS Total_Columns
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'Fact_Network_Flows';

SELECT TOP 10 *
FROM dbo.Fact_Network_Flows;


SELECT COUNT(*) AS Total_Flows
FROM dbo.Fact_Network_Flows;




SELECT
    COUNT(*) AS Total_Columns
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'Fact_Network_Flows';


select Flow_ID from  Fact_Network_Flows


-- Add Primary Key
ALTER TABLE dbo.Fact_Network_Flows
ADD CONSTRAINT PK_Fact_Network_Flows
PRIMARY KEY (Flow_ID);


SELECT
    fk.name AS ForeignKey,
    OBJECT_NAME(fk.parent_object_id) AS TableName,
    OBJECT_NAME(fk.referenced_object_id) AS ReferencedTable
FROM sys.foreign_keys fk
WHERE fk.parent_object_id =
    OBJECT_ID('dbo.Fact_Network_Flows');


    SELECT
    COLUMN_NAME,
    DATA_TYPE,
    IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'Fact_Network_Flows'
ORDER BY ORDINAL_POSITION;



SELECT COUNT(*)
FROM dbo.[cleaned_data_v1 - cleaned_cic_ids2017];

SELECT COUNT(*)
FROM dbo.Fact_Network_Flows;

SELECT DISTINCT t.label
FROM dbo.[cleaned_data_v1 - cleaned_cic_ids2017] t
LEFT JOIN dbo.Dim_Label d
    ON t.label = d.label
WHERE d.Label_ID IS NULL;