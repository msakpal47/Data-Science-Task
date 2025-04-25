

select * from users

select * from devices

SELECT * FROM access_logs

select * from threat_alerts

---1)-List all users and the number of devices assigned to each---

SELECT u.username, COUNT(d.device_id) AS device_count
FROM users u
LEFT JOIN devices d ON u.user_id = d.user_id
GROUP BY u.username;

---2)-------. Show the number of access logs recorded for each device---

SELECT device_id, COUNT(*) AS log_count
FROM access_logs
GROUP BY device_id;

----3)---Identify departments that have users with the most high severity threats

SELECT u.department, COUNT(*) AS high_threat_count
FROM threat_alerts t
JOIN devices d ON t.device_id = d.device_id
JOIN users u ON d.user_id = u.user_id
WHERE t.threat_level = 'high'
GROUP BY u.department
ORDER BY high_threat_count DESC;

-----4. Show users whose devices have had more than one high severity threat

SELECT u.username, COUNT(*) AS high_threat_count
FROM threat_alerts t
JOIN devices d ON t.device_id = d.device_id
JOIN users u ON d.user_id = u.user_id
WHERE t.threat_level = 'high'
GROUP BY u.username
HAVING COUNT(*) > 1;


-------5. Identify all users who experienced a high severity threat on one of their devices within 10 minutes after a login event



SELECT DISTINCT 
    u.username, 
    u.department, 
    d.device_type,
    a.access_time AS login_time, 
    t.detected_time AS threat_time, 
    t.threat_type
FROM 
    threat_alerts t
JOIN 
    devices d ON t.device_id = d.device_id
JOIN 
    access_logs a ON t.device_id = a.device_id
JOIN 
    users u ON d.user_id = u.user_id
WHERE 
    t.threat_level = 'high'
    AND a.access_type = 'login'
    AND t.detected_time BETWEEN a.access_time AND DATEADD(MINUTE, 10, a.access_time);

