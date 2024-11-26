const HOST = 'https://omar.eromo.tech';
document.addEventListener('DOMContentLoaded', () => {
    const weatherForm = document.getElementById('weather-form');
    const weatherResults = document.getElementById('weather-results');
    const forecastContainer = document.getElementById('forecast-container');

    weatherForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        // Get latitude and longitude from the form
        const latitude = document.getElementById('latitude').value;
        const longitude = document.getElementById('longitude').value;

        // Clear previous results
        forecastContainer.innerHTML = '';
        weatherResults.style.display = 'none';

        try {
            // Fetch weather data
            const response = await fetch(`${HOST}/api/v1/weather/${latitude}/${longitude}`);
            if (!response.ok) {
                throw new Error(`Error: ${response.status} ${response.statusText}`);
            }

            const data = await response.json();
            const periods = data.properties?.periods || [];

            if (periods.length === 0) {
                forecastContainer.innerHTML = '<p class="text-center text-danger">No forecast data available.</p>';
                weatherResults.style.display = 'block';
                return;
            }

            // Populate forecast data
            periods.forEach(period => {
                const card = document.createElement('div');
                card.className = 'forecast-card col-md-4';

                // Extract wind details
                const wind = period.windSpeed && period.windDirection
                    ? `${period.windSpeed} from ${period.windDirection}`
                    : "N/A";

                card.innerHTML = `
                    <img src="${period.icon}" alt="${period.shortForecast}" title="${period.shortForecast}">
                    <h4>${period.name}</h4>
                    <p><strong>Temperature:</strong> ${period.temperature}&deg;${period.temperatureUnit}</p>
                    <p><strong>Forecast:</strong> ${period.shortForecast}</p>
                    <p><strong>Wind:</strong> ${wind}</p>
                    <p>${period.detailedForecast}</p>
                `;
                forecastContainer.appendChild(card);
            });

            weatherResults.style.display = 'block';
        } catch (error) {
            forecastContainer.innerHTML = `<p class="text-center text-danger">Error fetching weather data: ${error.message}</p>`;
            weatherResults.style.display = 'block';
        }
    });
});
