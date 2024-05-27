  The Query solves the issue of fetching vulnerabilities with all or selected asset_groups.

WITH 
   group_asset_summary as 
 (
  SELECT DISTINCT
    dag.asset_group_id,
    dag.name,
    da.ip_address,
    da.host_name,
    fa.asset_id
  FROM
    fact_asset as fa
    JOIN dim_asset da USING (asset_id)
    JOIN dim_asset_group_asset USING (asset_id)
    JOIN dim_asset_group dag USING (asset_group_id)
 )


SELECT 
 a."Asset_Group_Name"
,a."IP_Address"
,a."Host_Name"
,a."Vulnerability_Id"
,a."Vulnerability_Title"
,a."Vulnerability_Description"
,a."Proof"
,a."Risk_Score"
,a."CVSSv3"
,a."Exploits"
,a."Malware_Kits"
,a."Row_No"
FROM

(
SELECT *,
 ROW_NUMBER() OVER(PARTITION BY Inner_Query."Vulnerability_Id") AS "Row_No"
 from
     (


SELECT DISTINCT 
 gas.name AS "Asset_Group_Name"
,gas.ip_address AS "IP_Address"
,gas.host_name AS "Host_Name"  
,dv.vulnerability_id AS "Vulnerability_Id"
,dv.title AS "Vulnerability_Title"
,proofAsText(dv.description) AS "Vulnerability_Description"
,proofAsText(favi.proof) AS "Proof"
,round(dv.riskscore::numeric, 0) AS "Risk_Score"
,round(dv.cvss_v3_score::numeric, 2) AS "CVSSv3"
,dv.exploits AS "Exploits"
,dv.malware_kits AS "Malware_Kits"

from fact_asset_vulnerability_instance favi 

Left Join dim_vulnerability dv ON dv.vulnerability_id = favi.vulnerability_id

Left Join group_asset_summary gas ON gas.asset_id = favi.asset_id

WHERE dv.riskscore >= 700 or dv.cvss_v3_score >= 7

GROUP BY gas.name,gas.ip_address,gas.host_name,dv.vulnerability_id,dv.title
        ,dv.description,dv.riskscore,dv.cvss_v3_score,dv.exploits,dv.malware_kits,favi.proof

) Inner_Query

) a
