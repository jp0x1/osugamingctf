function completeGameAndShowFlag() {
    try {
        // --- PART 1 & 2: YOUR WORKING CODE TO SET THE VISUAL STATE ---
        
        const masterClock = document.querySelector('div[style*="animation:289.544s"]');
        if (masterClock) {
            masterClock.style.animationDelay = '-288s';
        }

        const CLICKS_NEEDED = 740;
        const circles = document.querySelectorAll('details#n');
        if (circles.length < CLICKS_NEEDED) {
            alert("Error: Not enough circles found. Did you click 'start!' first?");
            return;
        }
        for (let i = 0; i < CLICKS_NEEDED; i++) {
            if(circles[i]) circles[i].setAttribute('open', '');
        }
        console.log("Visual score and rank have been set.");

        // --- PART 3: (THE FIX) ALIGN, SQUEEZE, READ, AND LOG THE FLAG ---
        
        setTimeout(() => {
            let flagString = '';
            const tumblers = document.querySelectorAll('div[style*="top:calc(400000% - 2984000px)"]');
            
            const sortedTumblers = Array.from(tumblers).sort((a, b) => parseInt(a.style.left) - parseInt(b.style.left));

            sortedTumblers.forEach((tumbler, i) => {
                // 1. Move the tumbler up.
                tumbler.style.top = '100px';
                
                // 2. Shift it left with less spacing for the smaller font.
                const horizontalPosition = 10 + (i * 12); // Reduced spacing from 18 to 12.
                tumbler.style.left = `${horizontalPosition}px`;

                // 3. **(NEW)** Squeeze it vertically by reducing the font size.
                tumbler.style.fontSize = '20px'; // Reduced font size from 30px to 20px.

                // 4. Read the visible character.
                const containerRect = tumbler.getBoundingClientRect();
                for (const charDiv of tumbler.children) {
                    const charRect = charDiv.getBoundingClientRect();
                    if (charRect.top >= containerRect.top && charRect.bottom <= containerRect.bottom + 2) {
                        flagString += charDiv.textContent;
                        break;
                    }
                }
            });

            // 5. Log the final extracted flag.
            console.log("The flag is:", flagString);
            alert("The flag has been aligned, squeezed, and logged to the console.");

        }, 200);

    } catch (error) {
        console.error("An error occurred:", error);
    }
}

// Run the function.
completeGameAndShowFlag();

just need a score of 7400 to win, so we just set it to 7400, and adjust the CSS of the outputted flag