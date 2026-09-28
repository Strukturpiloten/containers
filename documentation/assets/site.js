"use strict";

const search = document.querySelector("#image-search");
if (search) {
  const family = document.querySelector("#family-filter");
  const mode = document.querySelector("#mode-filter");
  const rows = [...document.querySelectorAll(".image-table tbody tr")];
  const count = document.querySelector("#result-count");
  const filter = () => {
    const terms = search.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
    let visible = 0;
    for (const row of rows) {
      const matches = terms.every(term => row.textContent.toLowerCase().includes(term)) &&
        (!family.value || row.dataset.family === family.value) &&
        (!mode.value || row.dataset.mode === mode.value);
      row.hidden = !matches;
      if (matches) visible++;
    }
    count.textContent = `${visible} of ${rows.length} images`;
    for (const group of document.querySelectorAll(".image-group")) {
      group.hidden = ![...group.querySelectorAll("tbody tr")].some(row => !row.hidden);
    }
    document.querySelector("#no-results").hidden = visible !== 0;
  };
  for (const control of [search, family, mode]) control.addEventListener("input", filter);
  filter();
}
