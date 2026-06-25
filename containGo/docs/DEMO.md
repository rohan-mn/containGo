# End-to-End Demonstration

## 1. Start everything

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-CONTAINGO.ps1
```

## 2. Demonstrate a normal Order Client request

1. Open **Architecture**.
2. Click **Order Client**.
3. Select `GET /api/orders`.
4. Click **Send request job**.
5. Return to the Architecture tab.
6. Observe Order Client → Gateway → OPA → Protected API and Gateway → Control Plane.
7. Inspect the TLS 1.3 and SPIFFE metadata in the trace panel.

## 3. Demonstrate method and route authorization

From Report Client, send `GET /api/reports`; it is allowed. Then select `GET /api/orders`; it is denied because Report Client does not own that route.

## 4. Quarantine Report Client

1. Open Report Client.
2. Click **Run quarantine sequence**.
3. The client first attempts `GET /api/payment-details`, adding 65 points.
4. It then attempts `PUT /api/admin/config`, adding another 60 points.
5. The total becomes 125 and Report Client is quarantined.
6. Send the normally allowed `GET /api/reports`; OPA now denies it because quarantine status is true.

## 5. Prove blast-radius containment

While Report Client is quarantined, open Order Client and send `GET /api/orders`. It continues to work because containment is applied to a specific authenticated workload identity.

## 6. Inspect and release

1. Open **Control Panel**.
2. Inspect Report Client's score, denial count, incident, and event evidence.
3. Click **Release**.
4. Return to Report Client and send `GET /api/reports` again.
5. The request succeeds and the score has reset to zero.

## 7. Demonstrate a behavioral rate anomaly

1. Open either client.
2. Click **Load rate burst**.
3. Send the job.
4. More than 20 requests inside five seconds adds 50 risk points even when the routes are normally authorized.

## 8. Demonstrate continuous traffic

1. Choose an allowed route.
2. Check **Continuous until stopped**.
3. Set concurrency and interval.
4. Start the job.
5. Observe live evidence.
6. Click **Cancel running job**. The executor also stops automatically after the configured maximum, capped at ten minutes.
