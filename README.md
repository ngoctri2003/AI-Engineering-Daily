# AI Engineering Daily bot (pilot)

Bot tự nghiên cứu, kiểm chứng, lọc và đăng bản tin AI + Software Engineering theo bộ rule của chị Quyên (AO-17).

Chi phí: GitHub Actions (repo public không giới hạn phút; repo private có hạn mức free) và Slack bot token không tốn tiền. Phần LLM: Gemini free tier là 0 đồng; Claude API tính tiền theo token và cần nạp credit trên platform.claude.com (credit hết hạn sau 1 năm). Số tiền thực tế xem ở trang Usage của Console sau vài lần chạy.

## Cách hoạt động
1. `app/sources.py` đọc feed Atom/RSS và trang changelog trong `app/sources.json`, lọc 48 giờ.
2. `app/llm.py` gọi 1 request LLM (system prompt = `app/rules.md`) để chọn tin và viết nội dung dạng JSON.
3. `app/formatter.py` kiểm tra checklist (label, tag, 50-80 từ, em dash, emoji, link phải nằm trong dữ liệu nguồn, primary source, 48h) rồi tự ghép định dạng Slack. Tin trượt thì sửa 1 lần, vẫn trượt thì loại.
4. `app/slack.py` đăng bản tin vào channel allow-list, chỉ đăng bản tin; ghi chú tin bị loại/nguồn lỗi chỉ nằm trong log Actions. Dòng xu hướng được viết sau khi chốt tin.
5. `state/posted.json` lưu tin đã đăng để không đăng lại.

## Cài đặt (khoảng 20 phút)
1. Tạo Slack app (api.slack.com/apps, From scratch, workspace dssolutioninc). Tên hiển thị: `AI Engineering Daily`. Scope Bot Token: `chat:write`. Install to Workspace, copy Bot User OAuth Token.
2. Vào channel test `C0C5RGC88SX`, gõ `/invite @AI Engineering Daily`.
3. Lấy API key LLM: Gemini tại aistudio.google.com (free tier, không cần thẻ), hoặc Claude tại platform.claude.com (tạo workspace và API key riêng cho bot, đặt spend limit hằng tháng).
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
python -m app.main --dry-run --mock tests/fixture.json         # chạy offline với dữ liệu giả
LLM_API_KEY=... python -m app.main --dry-run                   # chạy thật nhưng không đăng
```

## Đổi LLM
- `LLM_PROVIDER=gemini` (mặc định). Đặt `LLM_MODEL` và `LLM_FALLBACK_MODEL` theo model có trong trang Rate Limit của AI Studio (hiện dùng `gemini-3.8-flash` và `gemini-3.5-flash-lite`). Khi gặp 401/403, code tự thử 3 kiểu gửi key (header `x-goog-api-key`, `Authorization: Bearer`, `?key=`) và nhớ kiểu đúng.
- `LLM_PROVIDER=openai` với `LLM_BASE_URL` và `LLM_API_KEY`: dùng cho GitHub Models, Groq, OpenRouter hoặc endpoint tương thích OpenAI.
- `LLM_PROVIDER=anthropic`: gọi Claude Messages API (`https://api.anthropic.com/v1/messages`). Mặc định `LLM_MODEL=claude-sonnet-5-5`, `LLM_FALLBACK_MODEL=claude-haiku-5-5` (đặt biến để đổi; để trống thì dùng mặc định theo provider). `LLM_API_KEY` là API key tạo trên Console.
  - Code không gửi `temperature`/`top_p`/`top_k` (giá trị khác mặc định bị API trả HTTP 400) và không gửi `thinking`, nên model dùng thinking mặc định; token thinking tính tiền như token đầu ra.
  - Tùy chọn `LLM_EFFORT` (`low`, `medium`, `high`, `xhigh`, `max`) điều chỉnh độ sâu suy luận và chi phí; để trống thì dùng mặc định của model. Mức hợp lệ tùy model, sai mức thì API trả HTTP 400.
  - Chuyển từ Gemini sang Claude: đổi secret `LLM_API_KEY` thành key Claude, rồi đặt biến `LLM_PROVIDER=anthropic` (và bỏ `LLM_MODEL`, `LLM_FALLBACK_MODEL` cũ của Gemini nếu đang đặt). Quay lại Gemini: đặt `LLM_PROVIDER=gemini` và đổi lại secret.

## Việc cần kiểm tra ở lần chạy thật đầu tiên
- URL trong `sources.json` chưa được thử trực tiếp (môi trường dựng bot không truy cập được các site này). Log mỗi lần chạy in trạng thái từng nguồn; sửa/bỏ nguồn lỗi.
- Tên model Gemini và hạn mức free tier thay đổi theo thời gian, kiểm tra trên aistudio.google.com. Tên model Claude kiểm tra ở trang Models của Console.
- Với Claude: chạy dry-run vài lần, xem trang Usage trên Console để biết chi phí thực tế và kiểm tra log có dòng `[llm] model claude-... failed` hay không.
- `app/rules.md` là bản chép từ comment AO-17 (bị cắt ở mục 12). Bản gốc trong thread của chị Quyên là chuẩn.
- Cách tính 50-80 từ: phần mô tả + Đáng chú ý + Nên thử + Lưu ý (không tính headline). Hỏi chị Quyên nếu muốn khác.
