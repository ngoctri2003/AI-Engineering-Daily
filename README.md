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

## Manual send (web form)
A small Vercel project sends a hand-written message (title + message) through the same Slack bot, next to the daily run. Files: `public/index.html` (form), `api/send.py` (endpoint), `api/channels.py` (channel picker list), `app/auth.py` + `api/login.py` / `logout.py` / `session.py` (login), `app/manual.py` (checks), `slack.post` / `slack.schedule` (Slack calls).
1. Import this repo into Vercel (preset "Other", no build command).
2. Set environment variables in Vercel: `SLACK_BOT_TOKEN` and `SLACK_CHANNEL_ID` (the default channel). `SLACK_ALLOWED_CHANNELS` is no longer needed for the web form (see Channel picker); the daily run still uses it.
3. Open the deployed URL, fill Title and Message, optionally pick a schedule time, press Send / Schedule. Scheduling uses Slack `chat.scheduleMessage` (1 minute to 120 days ahead), so no extra cron is needed.

**Channel picker.** The form has a Channel dropdown (also on the Posted messages tab), so changing the target channel needs no env change or redeploy. The list comes from `users.conversations` and contains the public and private channels the bot is a member of (invite the bot with `/invite @bot` to make a channel appear). It needs the bot scopes `channels:read` and `groups:read`; reinstall the Slack app after adding them. The server re-checks that a picked channel is one of those, which replaces the `SLACK_ALLOWED_CHANNELS` check for manual sends. The dropdown preselects the last choice (kept in the browser), else `SLACK_CHANNEL_ID`. If the list cannot be loaded, the page warns and sends to `SLACK_CHANNEL_ID`. The Posted and Scheduled lists and Cancel follow the selected channel. The daily run (`app.main`, `app.alert`) is unchanged and still uses `SLACK_CHANNEL_ID` / `SLACK_ALLOWED_CHANNELS`.

**Editing a scheduled message.** Posted messages tab, Scheduled list, Edit button: the message opens in the form (title, text, time; the form stays on Schedule) and Save changes replaces it. Slack has no API to edit a scheduled message, so `app.manual.edit` (`POST /api/edit`) schedules the new version first and then cancels the original with `chat.deleteScheduledMessage`. If the new version is refused (for example a time that is too close), the original stays untouched. If only the cancel step fails, the new version is scheduled and the page says to cancel the original by hand, so a message is never lost. If the original was already sent or cancelled, nothing is created. Limits: Slack does not return the images of a scheduled message, so images of the original are not kept and must be added again; the new version gets a new Slack id. The target channel can be changed while editing.

**Login.** The page asks for an email and password. Every `/api` endpoint (send, edit, cancel, messages, channels) answers 401 without a valid session, so the static page alone shows and sends nothing. Accounts are not in the code: they come from two Vercel environment variables, and no password is stored anywhere, only PBKDF2-SHA256 hashes.
1. Run `python tools/hash_password.py <email> [<email> ...]` on your own computer. It asks for each password without echo and prints two lines, `AUTH_USERS=...` (JSON, email to hash) and `AUTH_SECRET=...` (random, signs the session cookie).
2. Add both as Vercel environment variables (mark them sensitive) and redeploy. Never commit them.
3. Sessions last 8 hours (`app/auth.py`, `SESSION_SECONDS`) in a signed `HttpOnly`, `Secure`, `SameSite=Strict` cookie. Nothing is stored on the server, so a session also ends when the user is removed from `AUTH_USERS` or `AUTH_SECRET` is changed (which signs everyone out). Sign out clears the cookie in that browser only.
- Fail closed: if `AUTH_USERS` or `AUTH_SECRET` is missing, malformed, or `AUTH_SECRET` is under 32 characters, every endpoint answers 503 and the page says login is not configured. The page is locked, not open, until both are set.
- Passwords up to 256 characters; emails are not case sensitive; a wrong login waits 1 second, and an unknown email costs the same time as a wrong password. Vercel keeps no shared counter between instances, so also add a rate limit rule for `/api/login` in the Vercel firewall.
- To add or remove a user or change a password, rerun the script for all users, update `AUTH_USERS`, and redeploy. Use a long unique password for each person; a short shared one can be guessed even through a rate limit.
- Cross-site requests are refused (`SameSite=Strict` plus an `Origin` check on every POST). `GET /api/session` tells the page whether it is signed in.
- This login protects the page and the Slack bot behind it. Vercel Deployment Protection can still be added on top. Manual messages are not written to `state/posted.json`. Limits: title 150, message 3500 characters.

**Images.** The form accepts up to 10 images (file picker, drag and drop, or paste). The browser resizes them to JPEG (GIFs become a still image) so the request stays under the 4.5 MB Vercel body limit (about 3 MB of images in total). The server uploads them with `files.getUploadURLExternal` / `files.completeUploadExternal` and attaches them as `image` blocks (`slack_file`), so this works for both Send now and Schedule. It needs the extra bot scope `files:write`; reinstall the Slack app after adding it. Images need the bot token (they are not supported through `SLACK_WEBHOOK_URL`).

The Posted messages section shows two lists, Posted (recent bot messages, click one to expand, with an Open in Slack link and image count) and Scheduled. They come from Slack: scheduled messages (`chat.scheduledMessages.list`, with a Cancel button) and posted messages (`conversations.history`, tagged Daily or Manual). Reading sent history needs the extra bot scope `channels:history` (public channel) or `groups:history` (private channel); reinstall the Slack app after adding it. Without it the Scheduled list still works and the page shows a warning. Slack is the only source of truth, so nothing is stored on Vercel.

## Tech Stack Security Daily (profile `websec`, AO-72)
A second bulletin on the same engine. It reports security issues that affect the company tech stack (browsers, Node.js/npm, PHP, WordPress, Atlassian Data Center, AWS) and is posted as its own message in the shared channel.
- Run: `python -m app.main --profile websec [--dry-run] [--mock tests/fixture_websec.json]`. The default profile `ai-daily` is unchanged.
- Code owns the decisions: `app/secsources.py` fetches CISA KEV, GitHub advisories (global and per repository) and vendor feeds, then fills CVSS from `cvelistV5`; `app/websec.py` filters (in KEV, exploited in the wild, or CVSS >= 8.0), matches `profiles/websec/watchlist.json`, groups one patch drop into one batch, and caps the output at 3 detailed items plus a one-line block. The LLM only writes the text of the selected batches.
- Validation: the link, label, tags and CVE IDs come from the data, not from the LLM. Any CVE ID, version or score in the LLM text must appear in the batch data; an item that fails is degraded to a one-line entry. Already posted CVE IDs are stored in `state/posted-websec.json`.
- No batch in the detailed tier means no post.
- Files: `profiles/websec/{profile,watchlist,sources}.json`, `profiles/websec/rules.md` (draft, needs approval), the same workflow `.github/workflows/daily.yml` (manual trigger; input `bulletin` = `both` (default), `ai-daily` or `websec`; scheduling is still to be decided).
- Coverage today: Chrome (Chrome Releases feed, Critical/High lines only), Firefox (Mozilla advisories repository), Node.js (GitHub release notes of nodejs/node), npm packages in the watchlist (GitHub advisories), Next.js, Express and PHP (repository advisories), everything else only through CISA KEV. WordPress, Java/Maven, Composer and AWS need dedicated sources and watchlist packages.
- Combined message: `python -m app.main --with-security` posts ONE AI Engineering Daily message with up to 4 AI items plus up to 3 detailed security items (section "Cảnh báo bảo mật tech stack") and at most 3 one-line entries, so at most 7 items. The workflow input `bulletin=both` (default) does this; `websec` still runs the standalone security bulletin. If one section fails the other is still posted and the run then ends with an error so the alert fires.
- Hacker News (`hn-signal`) is a detection signal only: stories are matched to selected items by CVE ID or identical link and only raise the rank inside the same tier. They are never posted, never linked in the message, and unmatched popular stories are only printed in the run log as `[signal]`. Reddit and X are intentionally not used.
- Not yet implemented: Apple and Atlassian HTML parsers, the weekly npm roundup, and the source-freshness alert to the alert channel (stale sources are only marked in the run log).

The page has two tabs, Manual Slack Post and Posted messages. Styling uses Bootstrap 5.3.3 and Bootstrap Icons 1.11.3 (CSS only, loaded from cdnjs). The UI language defaults to Vietnamese with an EN switch: source strings in `public/index.html` are English, and Vietnamese text lives in `public/locales/vi.json` (key = English text). To add a language, add `public/locales/<code>.json` and a button with `data-lang`.
