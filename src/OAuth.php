<?php

namespace PHPMailer\PHPMailer;

use League\OAuth2\Client\Grant\RefreshToken;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;

/**
 * OAuth - OAuth2 authentication wrapper class.
 * Uses the oauth2-client package from the League of Extraordinary Packages.
 *
 * @see     https://oauth2-client.thephpleague.com
 */
class OAuth implements OAuthTokenProvider
{
    /**
     * An instance of the League OAuth Client Provider.
     *
     * @var AbstractProvider
     */
    protected ?AbstractProvider $provider = null;

    /**
     * The current OAuth access token.
     *
     * @var AccessToken|null
     */
    protected ?AccessToken $oauthToken = null;

    /**
     * The user's email address, usually used as the login ID
     * and also the from address when sending email.
     *
     * @var string
     */
    protected string $oauthUserEmail;

    /**
     * The client secret, generated in the app definition of the service you're connecting to.
     *
     * @var string
     */
    protected string $oauthClientSecret;

    /**
     * The client ID, generated in the app definition of the service you're connecting to.
     *
     * @var string
     */
    protected string $oauthClientId;

    /**
     * The refresh token, used to obtain new AccessTokens.
     *
     * @var string
     */
    protected string $oauthRefreshToken;

    /**
     * OAuth constructor.
     *
     * @param AbstractProvider $provider OAuth provider instance
     * @param array $options Associative array containing `userName`, `clientSecret`, `clientId`, and `refreshToken`
     */
    public function __construct(AbstractProvider $provider, array $options)
    {
        $this->provider = $provider;
        $this->oauthUserEmail = $options['userName'];
        $this->oauthClientSecret = $options['clientSecret'];
        $this->oauthClientId = $options['clientId'];
        $this->oauthRefreshToken = $options['refreshToken'];
    }

    /**
     * Check if the current token is valid (exists and not expired).
     *
     * @return bool
     */
    protected function isTokenValid(): bool
    {
        return $this->oauthToken !== null && !$this->oauthToken->hasExpired();
    }

    /**
     * Get the OAuth provider instance.
     *
     * @return AbstractProvider
     */
    protected function getProvider(): AbstractProvider
    {
        return $this->provider;
    }

    /**
     * Get a new RefreshToken.
     *
     * @return RefreshToken
     */
    protected function getGrant(): RefreshToken
    {
        return new RefreshToken();
    }

    /**
     * Get a new AccessToken with retry logic.
     *
     * @param int $maxRetries Maximum number of retries
     * @return AccessToken
     * @throws \RuntimeException If token retrieval fails after retries
     */
    protected function getTokenWithRetry(int $maxRetries = 3): AccessToken
    {
        $retries = 0;
        do {
            try {
                return $this->getProvider()->getAccessToken(
                    $this->getGrant(),
                    ['refresh_token' => $this->oauthRefreshToken]
                );
            } catch (\Exception $e) {
                $retries++;
                if ($retries >= $maxRetries) {
                    throw new \RuntimeException('Failed to retrieve access token after retries.', 0, $e);
                }
                sleep(pow(2, $retries)); // Exponential backoff
            }
        } while ($retries < $maxRetries);
    }

    /**
     * Generate a base64-encoded OAuth token.
     *
     * @return string
     */
    public function getOauth64(): string
    {
        if (!$this->isTokenValid()) {
            $this->oauthToken = $this->getTokenWithRetry();
        }

        return base64_encode(sprintf(
            "user=%s\001auth=Bearer %s\001\001",
            $this->oauthUserEmail,
            $this->oauthToken->getToken()
        ));
    }
}
