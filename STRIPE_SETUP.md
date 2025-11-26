# Stripe Payment Setup Guide

This guide explains how to configure Stripe for payment processing in the application.

## Where to Add Stripe Details

### For Local Development

Add Stripe credentials to the **backend `.env` file**:

```bash
cd backend
nano .env  # or use your preferred editor
```

Add these lines:

```env
STRIPE_SECRET_KEY=sk_test_...your_stripe_secret_key_here
STRIPE_PRICE_ID_10=price_...your_price_id_for_10_repos
STRIPE_PRICE_ID_20=price_...your_price_id_for_20_repos
```

### For Docker/Production

Add Stripe credentials to the **root `.env` file** (used by docker-compose):

```bash
# In project root directory
nano .env
```

Add the same variables:

```env
STRIPE_SECRET_KEY=sk_live_...your_stripe_secret_key_here
STRIPE_PRICE_ID_10=price_...your_price_id_for_10_repos
STRIPE_PRICE_ID_20=price_...your_price_id_for_20_repos
```

## Getting Your Stripe Credentials

### 1. Get Your Stripe Secret Key

1. Go to [Stripe Dashboard](https://dashboard.stripe.com/)
2. Navigate to **Developers** → **API keys**
3. Copy your **Secret key**:
   - Use `sk_test_...` for testing (development)
   - Use `sk_live_...` for production

### 2. Create Price IDs (Optional - Current Implementation Uses Dynamic Pricing)

The current implementation creates prices dynamically, but you can also use pre-created Stripe Price IDs.

#### Option A: Use Dynamic Pricing (Current - No Price IDs Needed)

The current code creates prices on-the-fly, so you **only need** `STRIPE_SECRET_KEY`. The `STRIPE_PRICE_ID_10` and `STRIPE_PRICE_ID_20` are optional.

#### Option B: Use Pre-created Price IDs

1. Go to [Stripe Dashboard](https://dashboard.stripe.com/)
2. Navigate to **Products** → **Add Product**
3. Create a product for "Enterprise Starter" (10 repos)
4. Set up recurring pricing: $1000/month
5. Copy the **Price ID** (starts with `price_...`)
6. Repeat for "Enterprise Pro" (20 repos) at $1500/month
7. Add these Price IDs to your `.env` file

## Environment Variables Summary

### Required:
- `STRIPE_SECRET_KEY` - Your Stripe secret API key

### Optional (if using pre-created prices):
- `STRIPE_PRICE_ID_10` - Price ID for 10-repo plan
- `STRIPE_PRICE_ID_20` - Price ID for 20-repo plan

## Testing Stripe Integration

### Test Mode

For local development, use Stripe **Test Mode**:

1. Get test API keys from [Stripe Dashboard](https://dashboard.stripe.com/test/apikeys)
2. Use test card numbers:
   - Success: `4242 4242 4242 4242`
   - Decline: `4000 0000 0000 0002`
   - Any future expiry date and any 3-digit CVC

### Production Mode

For production, use **Live Mode** keys:
- Use `sk_live_...` instead of `sk_test_...`
- Test with real cards in test mode first!

## Verification

After adding Stripe credentials:

1. **Restart the backend server:**
   ```bash
   # Local development
   cd backend
   source venv/bin/activate
   python main.py
   
   # Or with Docker
   docker-compose restart backend
   ```

2. **Test the checkout:**
   - Go to the Pricing page
   - Click "Subscribe Now"
   - You should be redirected to Stripe Checkout
   - If you see "Payment processing is not configured", check your `.env` file

## Troubleshooting

### "Payment processing is not configured"

- Check that `STRIPE_SECRET_KEY` is set in your `.env` file
- Make sure there are no extra spaces or quotes around the key
- Restart the backend server after adding credentials

### Checkout redirects but shows error

- Verify your Stripe secret key is correct
- Check Stripe Dashboard for any API errors
- Ensure you're using the correct mode (test vs live)

### Price IDs not working

- The current implementation works without Price IDs (creates prices dynamically)
- If you want to use Price IDs, make sure they're valid and active in your Stripe account

## Security Notes

⚠️ **Important:**
- Never commit `.env` files to version control
- Keep your Stripe secret keys secure
- Use test keys for development
- Rotate keys if they're ever exposed

## Example .env File

```env
# Stripe Configuration
STRIPE_SECRET_KEY=sk_test_51AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefghijklmnopqrstuvwxyz
STRIPE_PRICE_ID_10=price_1234567890abcdef
STRIPE_PRICE_ID_20=price_abcdef1234567890
```

