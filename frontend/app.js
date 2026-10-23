// =====================================================================
// 1. ZAKŁADKI: Szyfruj / Odszyfruj / Klucz
// =====================================================================

// Wszystkie przyciski zakładek (mają klasę "tab")
const tabs = document.querySelectorAll(".tab");

// Trzy panele, które pokazujemy i chowamy
const panelEncrypt = document.getElementById("panel-encrypt");
const panelDecrypt = document.getElementById("panel-decrypt");
const panelKey = document.getElementById("panel-key");

// Każdemu przyciskowi zakładki dodajemy reakcję na kliknięcie
for (const tab of tabs) {
  tab.addEventListener("click", function () {
    // Najpierw wyłączamy wszystkie zakładki...
    for (const otherTab of tabs) {
      otherTab.classList.remove("active");
      otherTab.setAttribute("aria-selected", "false");
    }

    // ...a potem włączamy tę klikniętą
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");

    // Chowamy wszystkie panele
    panelEncrypt.hidden = true;
    panelDecrypt.hidden = true;
    panelKey.hidden = true;

    // Pokazujemy panel, którego nazwa jest w atrybucie data-tab
    if (tab.dataset.tab === "encrypt") {
      panelEncrypt.hidden = false;
    }
    if (tab.dataset.tab === "decrypt") {
      panelDecrypt.hidden = false;
    }
    if (tab.dataset.tab === "key") {
      panelKey.hidden = false;
    }
  });
}


// =====================================================================
// 2. SZYFROWANIE: POST /api/encrypt
// =====================================================================

const encryptPassword = document.getElementById("encrypt-password");
const encryptKey = document.getElementById("encrypt-key");
const encryptBtn = document.getElementById("encrypt-btn");
const encryptError = document.getElementById("encrypt-error");
const encryptErrorText = document.getElementById("encrypt-error-text");
const encryptResult = document.getElementById("encrypt-result");

encryptBtn.addEventListener("click", async function () {
  // Chowamy stary wynik i stary błąd
  encryptResult.hidden = true;
  encryptError.hidden = true;
  encryptKey.classList.remove("invalid");

  // Sprawdzamy, czy hasło nie jest puste, zanim cokolwiek wyślemy
  if (encryptPassword.value === "") {
    encryptErrorText.textContent = "Wpisz hasło, które chcesz zaszyfrować.";
    encryptError.hidden = false;
    return;
  }

  // Dane do wysłania. Klucz dodajemy tylko wtedy, gdy ktoś go wpisał,
  // bo backend sam wygeneruje nowy, jeśli go nie dostanie.
  const data = { password: encryptPassword.value };
  if (encryptKey.value !== "") {
    data.key = encryptKey.value.trim();
  }

  // Przycisk w stanie "ładowania"
  encryptBtn.disabled = true;
  encryptBtn.classList.add("loading");
  encryptBtn.textContent = "Szyfrowanie…";

  try {
    // Wysyłamy zapytanie do backendu
    const response = await fetch("/api/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });

    // Zamieniamy odpowiedź z JSON na obiekt JavaScript
    const body = await response.json();

    if (response.ok) {
      // Sukces (status 200): wpisujemy wyniki do ramek i pokazujemy je
      document.getElementById("result-ciphertext").textContent = body.encrypted_password;
      document.getElementById("result-nonce").textContent = body.nonce;
      document.getElementById("result-key").textContent = body.key;
      encryptResult.hidden = false;
    } else {
      // Błąd 400 z naszego exception handlera: detail to zwykły tekst.
      // Błąd 422 z walidacji Pydantic: detail to lista, więc piszemy własny tekst.
      if (typeof body.detail === "string") {
        encryptErrorText.textContent = body.detail;
        encryptKey.classList.add("invalid");
      } else {
        encryptErrorText.textContent = "Hasło musi mieć od 1 do 1024 znaków.";
      }
      encryptError.hidden = false;
    }
  } catch (error) {
    // Tu trafiamy, gdy serwer w ogóle nie odpowiedział
    encryptErrorText.textContent = "Serwer nie odpowiada. Spróbuj ponownie za chwilę.";
    encryptError.hidden = false;
  }

  // Przywracamy przycisk do normalnego stanu
  encryptBtn.disabled = false;
  encryptBtn.classList.remove("loading");
  encryptBtn.textContent = "Zaszyfruj";
});


// =====================================================================
// 3. PRZYCISK "GENERUJ" OBOK POLA KLUCZA: GET /api/key
// =====================================================================

const encryptGenerateKeyBtn = document.getElementById("encrypt-generate-key-btn");

encryptGenerateKeyBtn.addEventListener("click", async function () {
  encryptError.hidden = true;
  encryptKey.classList.remove("invalid");

  try {
    const response = await fetch("/api/key");
    const key = await response.json();

    // Endpoint zwraca sam tekst klucza, więc wpisujemy go prosto do pola
    encryptKey.value = key;
  } catch (error) {
    encryptErrorText.textContent = "Serwer nie odpowiada. Spróbuj ponownie za chwilę.";
    encryptError.hidden = false;
  }
});


// =====================================================================
// 4. ODSZYFROWANIE: POST /api/decrypt
// =====================================================================

const decryptCiphertext = document.getElementById("decrypt-ciphertext");
const decryptNonce = document.getElementById("decrypt-nonce");
const decryptKey = document.getElementById("decrypt-key");
const decryptBtn = document.getElementById("decrypt-btn");
const decryptError = document.getElementById("decrypt-error");
const decryptErrorText = document.getElementById("decrypt-error-text");
const decryptResult = document.getElementById("decrypt-result");

decryptBtn.addEventListener("click", async function () {
  decryptResult.hidden = true;
  decryptError.hidden = true;

  // Wszystkie trzy pola są wymagane
  if (decryptCiphertext.value === "" || decryptNonce.value === "" || decryptKey.value === "") {
    decryptErrorText.textContent = "Wypełnij wszystkie trzy pola: szyfrogram, nonce i klucz.";
    decryptError.hidden = false;
    return;
  }

  // .trim() usuwa spacje z początku i końca (częste przy wklejaniu)
  const data = {
    ciphertext: decryptCiphertext.value.trim(),
    nonce: decryptNonce.value.trim(),
    key: decryptKey.value.trim(),
  };

  decryptBtn.disabled = true;
  decryptBtn.classList.add("loading");
  decryptBtn.textContent = "Odszyfrowywanie…";

  try {
    const response = await fetch("/api/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });

    const body = await response.json();

    if (response.ok) {
      document.getElementById("result-password").textContent = body.decrypted_password;
      decryptResult.hidden = false;
    } else {
      if (typeof body.detail === "string") {
        decryptErrorText.textContent = body.detail;
      } else {
        decryptErrorText.textContent = "Niepoprawne dane. Sprawdź wszystkie pola.";
      }
      decryptError.hidden = false;
    }
  } catch (error) {
    decryptErrorText.textContent = "Serwer nie odpowiada. Spróbuj ponownie za chwilę.";
    decryptError.hidden = false;
  }

  decryptBtn.disabled = false;
  decryptBtn.classList.remove("loading");
  decryptBtn.textContent = "Odszyfruj";
});


// =====================================================================
// 5. ZAKŁADKA "KLUCZ": GET /api/key
// =====================================================================

const keyBtn = document.getElementById("key-btn");
const keyError = document.getElementById("key-error");
const keyErrorText = document.getElementById("key-error-text");
const keyResult = document.getElementById("key-result");

keyBtn.addEventListener("click", async function () {
  keyError.hidden = true;

  keyBtn.disabled = true;
  keyBtn.classList.add("loading");
  keyBtn.textContent = "Generowanie…";

  try {
    const response = await fetch("/api/key");
    const key = await response.json();

    document.getElementById("result-new-key").textContent = key;
    keyResult.hidden = false;
  } catch (error) {
    keyErrorText.textContent = "Serwer nie odpowiada. Spróbuj ponownie za chwilę.";
    keyError.hidden = false;
  }

  keyBtn.disabled = false;
  keyBtn.classList.remove("loading");
  keyBtn.textContent = "Generuj klucz";
});


// =====================================================================
// 6. PRZYCISKI "KOPIUJ"
// =====================================================================

// Każdy przycisk "Kopiuj" ma atrybut data-copy z id elementu,
// którego tekst ma skopiować, np. data-copy="result-nonce"
const copyButtons = document.querySelectorAll(".btn-copy");
const toast = document.getElementById("toast");

for (const button of copyButtons) {
  button.addEventListener("click", async function () {
    const element = document.getElementById(button.dataset.copy);

    // Kopiujemy tekst do schowka
    await navigator.clipboard.writeText(element.textContent);

    // Przycisk na chwilę zmienia się w "Skopiowano"
    button.textContent = "Skopiowano";
    button.classList.add("copied");

    // Pokazujemy dymek w prawym dolnym rogu
    toast.hidden = false;

    // Po 1,5 sekundy wszystko wraca do normy
    setTimeout(function () {
      button.textContent = "Kopiuj";
      button.classList.remove("copied");
      toast.hidden = true;
    }, 1500);
  });
}