# AI Engineering Daily bot (pilot)

Bot tự nghiên cứu, kiểm chứng, lọc và đăng bản tin AI + Software Engineering theo bộ rule của chị Quyên (AO-17).

Chi phí: 0 đồng nếu dùng GitHub Actions (repo public không giới hạn phút; repo private có hạn mức free), Gemini free tier và Slack bot token.

## Cách hoạt động
1. `app/sources.py` đọc feed Atom/RSS và trang changelog trong `app/sources.json`, lọc 48 giờ.
2. `app/llm.py` gọi 1 request LLM (system prompt = `app/rules.md`) để chọn tin và viết nội dung dạng JSON.
3. `app/formatter.py` kiểm tra checklist (label, tag, 50-80 từ, em dash, emoji, link phải nằm trong dữ liệu nguồn, primary source, 48h) rồi tự ghép định dạng Slack. Tin trượt thì sửa 1 lần, vẫn trượt thì loại.
4. `app/slack.py` đăng bản tin vào channel allow-list, ghi chú tin bị loại/nguồn lỗi đăng thành reply trong thread (ngoài bản tin).
5. `state/posted.json` lưu tin đã đăng để không đăng lại.

## Cài đặt (khoảng 20 phút)
1. Tạo Slack app (api.slack.com/apps, From scratch, workspace dssolutioninc). Tên hiển thị: `AI Engineering Daily`. Scope Bot Token: `chat:write`. Install to Workspace, copy Bot User OAuth Token.
2. Vào channel test `C0C5RGC88SX`, gõ `/invite @AI Engineering Daily`.
3. Lấy API key Gemini tại aistudio.google.com (free tier, không cần thẻ).
4. Tạo repo GitHub, push thư mục này lên. Settings > Secrets and variables > Actions:
   - Secrets: `SLACK_BOT_TOKEN`, `LLM_API_KEY`
   - Variables (tùy chọn): `SLACK_CHANNEL_ID`, `SLACK_ALLOWED_CHANNELS`, `LLM_MODEL`, `LLM_FALLBACK_MODEL`, `LLM_PROVIDER`
5. Tab Actions > AI Engineering Daily > Run workflow (mặc định dry run, xem log). Khi ổn, bỏ tick dry_run để đăng thật.

Không đưa token vào code, README hay commit.

## Báo lỗi vào Slack
Khi lượt chạy theo lịch (hoặc chạy tay đã bỏ dry run) bị lỗi, bước cuối của workflow chạy `python -m app.alert` và gửi tin vào channel: ngày, lý do (đã che key/token) và link log. Mặc định gửi vào `SLACK_CHANNEL_ID`; muốn gửi chỗ khác, đặt biến `ALERT_CHANNEL_ID`. Ngày không có tin đủ chuẩn thì không đăng và không báo lỗi. Nếu chính Slack lỗi, dựa vào email thông báo của GitHub Actions.

## Chạy local
```
python -m unittest discover -s tests -v                       # test validator
FORCE=1 python -m app.main --dry-run --mock tests/fixture.json # chạy offline với dữ liệu giả
LLM_API_KEY=... FORCE=1 python -m app.main --dry-run           # chạy thật nhưng không đăng
```

## Đổi LLM
- `LLM_PROVIDER=gemini` (mặc định). Đặt `LLM_MODEL` và `LLM_FALLBACK_MODEL` theo model có trong trang Rate Limit của AI Studio (hiện dùng `gemini-3.8-flash` và `gemini-3.5-flash-lite`). Khi gặp 401/403, code tự thử 3 kiểu gửi key (header `x-goog-api-key`, `Authorization: Bearer`, `?key=`) và nhớ kiểu đúng.
- `LLM_PROVIDER=openai` với `LLM_BASE_URL` và `LLM_API_KEY`: dùng cho GitHub Models, Groq, OpenRouter hoặc endpoint tương thích OpenAI.
- Muốn dùng Claude API: thêm một hàm `_anthropic` trong `app/llm.py` (khoảng 15 dòng).

## Việc cần kiểm tra ở lần chạy thật đầu tiên
- URL trong `sources.json` chưa được thử trực tiếp (môi trường dựng bot không truy cập được các site này). Log mỗi lần chạy in trạng thái từng nguồn; sửa/bỏ nguồn lỗi.
- Tên model Gemini và hạn mức free tier thay đổi theo thời gian, kiểm tra trên aistudio.google.com.
- `app/rules.md` là bản chép từ comment AO-17 (bị cắt ở mục 12). Bản gốc trong thread của chị Quyên là chuẩn.
- Cách tính 50-80 từ: phần mô tả + Đáng chú ý + Nên thử + Lưu ý (không tính headline). Hỏi chị Quyên nếu muốn khác.
