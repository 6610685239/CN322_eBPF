# Integration Test Summary

สรุปการทดสอบระดับ Integration (repositories กับ SQLite in-memory)

## วัตถุประสงค์
- ยืนยันการทำงานร่วมกับฐานข้อมูลจริง (SQLite) ของ repositories
- ตรวจการ seed ค่าเริ่มต้น, CRUD, update และ logging behaviour

## คำสั่งเพื่อ reproduce

```bash
cd backend
npm install
# รันเฉพาะชุด integration tests
npx jest __tests__/integration --runInBand --coverage
# ผลลัพธ์ coverage อยู่ที่: backend/coverage/lcov-report/index.html
```

## ตารางสรุปการทดสอบ

| Repository | ทดสอบ (Test cases) | วัตถุประสงค์ | ผลลัพธ์ที่คาดหวัง |
|---|---|---|---|
| `BlacklistRepository` | create(ip,note); findAll(); findById(id); deleteById(id) | ตรวจ lifecycle ของ blacklist (insert → read → delete) | สร้าง row ได้, อ่านเจอ, ลบสำเร็จ |
| `FeatureFlagRepository` | seed defaults; findAllAsMap(); setEnabled(name,false) | ตรวจการ seed ค่า flag เริ่มต้น และการ toggle | ค่า seed ถูกสร้าง, `setEnabled` เปลี่ยนค่าได้ |
| `FloodRateRepository` | seed defaults; findAll(); findByType('udp_flood'); update(); addLog(); getLogs() | ตรวจ seed ของ flood types, อัปเดต limits และบันทึก log | ค่าพื้นฐานมีครบ (>=3 types), update คืน true, log ถูกบันทึก |

## ข้อจำกัด / ข้อสังเกต
- ใช้ฐานข้อมูล in-memory (`:memory:`) เพื่อแยกสภาพแวดล้อมและให้เทสรันได้เร็ว
- Integration tests นี้ครอบคลุม repository ↔ DB เท่านั้น — ยังไม่รวม service-layer ที่เรียก `ipc` หรือ eBPF interaction

ไฟล์ทดสอบที่เกี่ยวข้อง: `backend/__tests__/integration/repositories.integration.test.js`.
