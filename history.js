chrome.storage.local.get(["history"], function(result) {
  let history = result.history || [];
  let list = document.getElementById("historyList");

  if (history.length === 0) {
    list.innerText = "No scan history found";
    return;
  }

  list.innerHTML = "";

  history.forEach((item) => {
    let div = document.createElement("div");

    let className = "safe";
    if (item.level === "Suspicious") className = "suspicious";
    if (item.level === "High Risk") className = "danger";

    div.className = "item " + className;
    div.innerHTML =
      "<b>URL:</b> " + item.url + "<br>" +
      "<b>Risk:</b> " + item.risk + "<br>" +
      "<b>Level:</b> " + item.level + "<br>" +
      "<div class='time'>" + item.time + "</div>";

    list.appendChild(div);
  });
});