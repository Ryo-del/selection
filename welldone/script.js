(() => {
  const BASE = "185.96.80.7:8080"; 
  const form = document.querySelector("#entry-form");
  const input = document.querySelector("#entry-input");

  if (!form || !input) return;


  const initHandshake = async () => {
    try {
      const res = await fetch(`${BASE}/handshake`, {
        method: "GET",
        credentials: "include" 
      });
      const data = await res.json();
      console.log("Handshake GET:", data);
    } catch (err) {
      console.error("Handshake GET error:", err);
    }
  };

  initHandshake();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const value = input.value.trim();
    if (!value) return;

    try {
      const res = await fetch(`${BASE}/handshake`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "include", 
        body: JSON.stringify({ input: value })
      });

      if (res.status === 401 || res.status === 403) {
        input.value = "";
        alert("Unauthorized or forbidden");
        return;
      }

      const data = await res.json();

      if (data?.status === "incomplete") {
        input.value = "";
        alert("Incomplete, try again");
        return;
      }

      if (data?.next) {
        window.location.href = data.next;
      }
    } catch (err) {
      console.error("Handshake POST error:", err);
    }
  });
})();
