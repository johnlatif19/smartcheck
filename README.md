# SmartCheck Website

Professional device testing and diagnostics platform.

## Features
- Real-time device dashboard
- QR code pairing
- Device testing reports
- Secure JWT authentication
- Firebase Firestore integration

## Deployment to Vercel

1. Fork/clone this repository
2. Create a new project on Vercel
3. Add environment variables:
   - `SESSION_SECRET`: Your session secret (32+ chars)
   - `JWT_SECRET`: Your JWT secret (32+ chars)
   - `FIREBASE_CONFIG`: Your Firebase service account JSON
   - `PORT`: 3000

4. Deploy!

## Local Development

```bash
# Install dependencies
npm install

# Create .env file from .env.example
cp .env.example .env

# Add your Firebase config to .env

# Run development server
npm run dev

# Production
npm start
