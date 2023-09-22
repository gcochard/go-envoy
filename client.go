package envoy

import (
	"log"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
)

var (
	// ErrNotOK is returned if any of the Envoy APIs does not return a 200
	ErrNotOK = errors.New("server did not return 200")
)

// Client provides the API for interacting with the Envoy APIs
type Client struct {
	address string
	client  *http.Client
	token   string
	proto   string
	loggedin bool
}

// NewClient creates a new Client that will talk to an Envoy unit at *address*, creating its own http.Client underneath.
func NewClient(address string, proto string) *Client {
	insecureTr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	secureTr := &http.Transport{}
	var tr *http.Transport
	if proto == "https" {
		tr = insecureTr
	} else {
		tr = secureTr
	}
	client := &http.Client{Transport: tr}

	return &Client{
		address: address,
		client:  client,
		proto: proto,
	}
}

// NewClientWithHTTP creates a new Client that will talk to an Envoy unit at *address* using the provided http.Client.
func NewClientWithHTTP(address string, proto string, client *http.Client) *Client {
	return &Client{
		address: address,
		client:  client,
		proto: proto,
	}
}

func (c *Client) get(url string, response interface{}) error {
	resp, err := c.client.Get(fmt.Sprintf("%s://%s%s", c.proto, c.address, url))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// try once to log in
	if resp.StatusCode == http.StatusUnauthorized || !c.loggedin {
		c.loggedin = false
		c.Login()
		return c.get(url, response)
	}

	if resp.StatusCode != http.StatusOK {
		return ErrNotOK
	}

	return json.NewDecoder(resp.Body).Decode(response)
}

// Inventory returns the list of parts installed in the system and registered with the Envoy unit
func (c *Client) Inventory() ([]Inventory, error) {
	var inventory []Inventory
	err := c.get("/inventory.json?deleted=1", &inventory)
	return inventory, err
}

// Production returns the current data for Production and Consumption sensors, if equipped.
func (c *Client) Production() (Production, error) {
	var production Production
	err := c.get("/production.json?details=1", &production)
	return production, err
}

func (c *Client) SetToken(token string) {
	c.token = token
}
func (c *Client) Login() error {
	if c.loggedin && c.client.Jar != nil {
		log.Printf("Already logged in, skipping")
		return nil
	}
	authURI := fmt.Sprintf("%s://%s/auth/check_jwt", c.proto, c.address)
	req, err := http.NewRequest("GET", authURI, nil)
	if err != nil {
		return err
	}
	if c.client.Jar == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return err
		}
		c.client.Jar = jar
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	_, err = c.client.Do(req)
	c.loggedin = true
	return nil
}
