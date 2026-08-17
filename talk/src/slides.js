(() => {
	const slides = [...document.querySelectorAll("[data-slide]")];
	const currentLabel = document.querySelector("[data-current]");
	const cueLabel = document.querySelector("[data-cue-label]");
	const progress = document.querySelector("[data-progress]");
	const toast = document.querySelector("[data-toast]");
	let current = Number.parseInt(window.location.hash.slice(1), 10);

	if (!Number.isInteger(current) || current < 1 || current > slides.length) {
		current = 1;
	}

	const show = (next) => {
		current = Math.min(Math.max(next, 1), slides.length);

		for (const [index, slide] of slides.entries()) {
			slide.classList.toggle("is-active", index === current - 1);
		}

		currentLabel.textContent = String(current);
		cueLabel.textContent = slides[current - 1].dataset.cue;
		progress.style.width = `${(current / slides.length) * 100}%`;
		window.history.replaceState(null, "", `#${current}`);
	};

	const flash = (message) => {
		toast.textContent = message;
		toast.classList.add("is-visible");
		window.setTimeout(() => toast.classList.remove("is-visible"), 1100);
	};

	const copy = async (targetId) => {
		const target = document.getElementById(targetId);

		if (!target) {
			return;
		}

		await navigator.clipboard.writeText(target.textContent.trim());
		flash("Prompt copied");
	};

	document.addEventListener("click", (event) => {
		const button = event.target.closest("button");

		if (!button) {
			return;
		}

		if (button.dataset.action === "next") {
			show(current + 1);
		} else if (button.dataset.action === "prev") {
			show(current - 1);
		} else if (button.dataset.action === "notes") {
			document.body.classList.toggle("show-notes");
		} else if (button.dataset.copyTarget) {
			copy(button.dataset.copyTarget).catch(() => flash("Copy failed"));
		}
	});

	document.addEventListener("keydown", (event) => {
		if (event.target.matches("details, summary, button")) {
			return;
		}

		if (["ArrowRight", "PageDown", " "].includes(event.key)) {
			event.preventDefault();
			show(current + 1);
		} else if (["ArrowLeft", "PageUp"].includes(event.key)) {
			event.preventDefault();
			show(current - 1);
		} else if (event.key === "Home") {
			show(1);
		} else if (event.key === "End") {
			show(slides.length);
		} else if (event.key.toLowerCase() === "n") {
			document.body.classList.toggle("show-notes");
		} else if (event.key.toLowerCase() === "f") {
			document.documentElement.requestFullscreen().catch(() => {});
		}
	});

	window.addEventListener("hashchange", () => {
		const target = Number.parseInt(window.location.hash.slice(1), 10);

		if (Number.isInteger(target)) {
			show(target);
		}
	});

	show(current);
})();
