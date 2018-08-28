# Ouroboros REST API Documentation

This document describes the REST API and resources provided by Ouroboros CI. The
REST APIs are for developers who want to integrate Ouroboros CI into their
application and for administrators who want to script interactions with the
Ouroboros server.

Ouroboros's REST APIs provide access to resources (data entities) via URI paths.
To use a REST API, your application will make an HTTP request and parse the
response. The response format is JSON. Your methods will be the standard HTTP
methods like GET, PUT, POST and DELETE.

Because the REST API is based on open standards, you can use any web development
language to access the API.

**Create a job**
----
  Create and add new job.

* **URL**

  /api/v1/job

* **Method:**

  `POST`
  
*  **URL Params**

  None

* **Data Params**

  FIXME

* **Success Response:**

  * **Code:** 200 <br />
    **Content:** `{ id : 12 }`
 
* **Error Response:**

  * **Code:** 404 NOT FOUND <br />
    **Content:** `{ error : "User doesn't exist" }`

* **Sample Call:**

  ```json
  ```

**Get or delete a job**
----
  Returns json data about a job or delete it.

* **URL**

  /api/v1/job/:id

* **Method:**

  `GET|POST`
  
*  **URL Params**

   **Required:**
 
   `id=[integer]`

* **Data Params**

  None

* **Success Response:**

  * **Code:** 200 <br />
    **Content:** `{ id : 12, name : "Michael Bloom" }`
 
* **Error Response:**

  * **Code:** 404 NOT FOUND <br />
    **Content:** `{ error : "User doesn't exist" }`

* **Sample Call:**

  ```json
      ```

## Getting job metadata

GET to http://ouroboros/api/v1/meta/{id}/

## Listing all jobs

GET to http://ouroboros/api/v1/job

## Manually start a job

POST to http://ouroboros/api/v1/start/{id}/

## Manually stop a job

POST to http://ouroboros/api/v1/stop/{id}/
