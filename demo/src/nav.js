// Arrow-key slide navigation. Slides live at /0 .. /7; the appendix at
// /appendix is reachable with the "a" key. The URL is the slide state, so
// a mid-talk reload lands exactly where you were.
const LAST_SLIDE = 7;

document.addEventListener("keydown", (e) => {
	if (e.target.tagName === "INPUT") {
		return;
	}

	const here = parseInt(location.pathname.slice(1), 10);
	const current = Number.isNaN(here) ? 0 : here;

	if (e.key === "ArrowRight" || e.key === " " || e.key === "PageDown") {
		if (current < LAST_SLIDE) {
			location.href = "/" + (current + 1);
		}
	} else if (e.key === "ArrowLeft" || e.key === "PageUp") {
		if (current > 0) {
			location.href = "/" + (current - 1);
		}
	} else if (e.key === "a") {
		location.href = "/appendix";
	} else if (e.key === "0") {
		location.href = "/0";
	}
});
