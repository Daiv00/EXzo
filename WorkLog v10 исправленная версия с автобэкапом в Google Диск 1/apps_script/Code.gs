/**
 * WorkLog · автобэкап в Google Диск без Google Cloud.
 *
 * Как это работает:
 *   1. Ты вставляешь этот файл в script.google.com (Новый проект).
 *   2. Задаёшь свой секретный ключ в SECRET ниже.
 *   3. Публикуешь как веб-приложение (Развернуть → Новое развёртывание →
 *      Веб-приложение, «Запуск от имени: я», «Доступ: все»).
 *   4. Копируешь ссылку /exec и вставляешь её в WorkLog → Настройки.
 *
 * Приложение WorkLog присылает сюда JSON, а скрипт складывает его файлом
 * в папку на ТВОЁМ Диске. Никаких сервисных аккаунтов и биллинга.
 */

// ⚠️ ЗАМЕНИ на свой длинный случайный ключ и вставь такой же в WorkLog.
var SECRET = 'ЗАМЕНИ_МЕНЯ_НА_ДЛИННЫЙ_СЛУЧАЙНЫЙ_КЛЮЧ';

// Имя папки по умолчанию, если WorkLog его не передал.
var DEFAULT_FOLDER = 'WorkLog — Смены';

function doPost(e) {
  try {
    var body = JSON.parse((e && e.postData && e.postData.contents) || '{}');

    if (!SECRET || SECRET.indexOf('ЗАМЕНИ') === 0) {
      return json({ ok: false, error: 'В скрипте не задан SECRET' });
    }
    if (String(body.secret || '') !== SECRET) {
      return json({ ok: false, error: 'Неверный секретный ключ' });
    }

    var folder = getFolder(body.folder || DEFAULT_FOLDER);

    // Проверка связи из настроек WorkLog.
    if (body.ping) {
      return json({ ok: true, ping: true, folder: folder.getName(), folderUrl: folder.getUrl() });
    }

    var name = sanitize(body.filename || 'worklog.json');
    var content = JSON.stringify(body.data || {}, null, 2);
    var file = upsert(folder, name, content);

    // Копия «на всякий случай»: одна версия в день, чтобы Диск не засорялся.
    if (body.keepDaily !== false) {
      var stamp = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM-dd');
      var history = getFolder('История', folder);
      upsert(history, name.replace(/\.json$/i, '') + '-' + stamp + '.json', content);
    }

    return json({
      ok: true,
      file: file.getName(),
      fileUrl: file.getUrl(),
      folder: folder.getName(),
      folderUrl: folder.getUrl()
    });
  } catch (err) {
    return json({ ok: false, error: String(err) });
  }
}

function doGet() {
  return json({ ok: true, service: 'WorkLog backup', hint: 'Используй POST из приложения WorkLog' });
}

/** Найти папку по имени или создать её (при parent — внутри неё). */
function getFolder(name, parent) {
  var root = parent || DriveApp.getRootFolder();
  var it = root.getFoldersByName(name);
  return it.hasNext() ? it.next() : root.createFolder(name);
}

/** Перезаписать файл, если он уже есть, иначе создать новый. */
function upsert(folder, name, content) {
  var it = folder.getFilesByName(name);
  if (it.hasNext()) {
    var file = it.next();
    file.setContent(content);
    return file;
  }
  return folder.createFile(name, content, MimeType.PLAIN_TEXT);
}

function sanitize(name) {
  return String(name).replace(/[^\wа-яА-ЯёЁ .\-]/g, '_').slice(0, 120) || 'worklog.json';
}

function json(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
