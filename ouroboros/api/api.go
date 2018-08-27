package api

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/ligurio/ouroboros/job"
)

const (
	// Base API v1 Path
	ApiUrlPrefix = "/api/v1/"

	JobPath    = "job/"
	ApiJobPath = ApiUrlPrefix + JobPath

	contentType     = "Content-Type"
	jsonContentType = "application/json;charset=UTF-8"
)

type JobMetadataResponse struct {
	JobMetadata *job.Metadata `json:"job_metadata"`
}

// HandleListJobStatsRequest is the handler for getting job-specific stats
// /api/v1/job/meta/{id}
func HandleListJobStatsRequest(cache *job.JobCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		j, err := cache.Get(id)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		resp := &JobMetadataResponse{
			JobMetadata: &j.Metadata,
		}

		w.Header().Set(contentType, jsonContentType)
		w.WriteHeader(http.StatusOK)

		indentResp, err := json.MarshalIndent(resp, " ", " ")
		if err != nil {
			log.Errorf("Error occured when marshalling response: %s", err)
			return
		}
		if w.Write(indentResp); err != nil {
			log.Errorf("Error occured when writing response: %s", err)
			return
		}
	}
}

type ListJobsResponse struct {
	Jobs map[string]*job.Job `json:"jobs"`
}

// HandleListJobs responds with an array of all Jobs within the server,
// active or disabled.
func HandleListJobsRequest(cache *job.JobCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		allJobs := cache.GetAll()
		allJobs.Lock.RLock()
		defer allJobs.Lock.RUnlock()

		resp := &ListJobsResponse{
			Jobs: allJobs.Jobs,
		}

		w.Header().Set(contentType, jsonContentType)
		w.WriteHeader(http.StatusOK)

		indentResp, err := json.MarshalIndent(resp, " ", " ")
		if err != nil {
			log.Errorf("Error occured when marshalling response: %s", err)
			return
		}
		if w.Write(indentResp); err != nil {
			log.Errorf("Error occured when writing response: %s", err)
			return
		}

		return
	}
}

type AddJobResponse struct {
	Id string `json:"id"`
}

func unmarshalNewJob(r *http.Request) (*job.Job, error) {
	newJob := &job.Job{}

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		log.Errorf("Error occured when reading r.Body: %s", err)
		return nil, err
	}
	defer r.Body.Close()

	if err := json.Unmarshal(body, newJob); err != nil {
		log.Errorf("Error occured when unmarshalling data: %s", err)
		return nil, err
	}

	return newJob, nil
}

// HandleAddJob takes a job object and unmarshals it to a Job type,
// and then throws the job in the schedulers.
func HandleAddJob(cache *job.JobCache, defaultOwner string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newJob, err := unmarshalNewJob(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if defaultOwner != "" && newJob.Owner == "" {
			newJob.Owner = defaultOwner
		}

		//err = newJob.Init(&cache, &pool)
		if err != nil {
			errStr := "Error occured when initializing the job"
			log.Errorf(errStr+": %s", err)
			http.Error(w, errStr, http.StatusBadRequest)
			return
		}

		resp := &AddJobResponse{
			Id: newJob.Id,
		}

		w.Header().Set(contentType, jsonContentType)
		w.WriteHeader(http.StatusCreated)

		indentResp, err := json.MarshalIndent(resp, " ", " ")
		if err != nil {
			log.Errorf("Error occured when marshalling response: %s", err)
			return
		}
		if w.Write(indentResp); err != nil {
			log.Errorf("Error occured when writing response: %s", err)
			return
		}
	}
}

// HandleJobRequest routes requests to /api/v1/job/{id} to either
// handleDeleteJob if its a DELETE or handleGetJob if its a GET request.
func HandleJobRequest(cache *job.JobCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]

		j, err := cache.Get(id)
		if err != nil {
			log.Errorf("Error occured when trying to get the job you requested.")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if j == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Method == "DELETE" {
			// FIXME err = j.Delete(cache)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		} else if r.Method == "GET" {
			handleGetJob(w, r, j)
		}
	}
}

type JobResponse struct {
	Job *job.Job `json:"job"`
}

func handleGetJob(w http.ResponseWriter, r *http.Request, j *job.Job) {
	resp := &JobResponse{
		Job: j,
	}

	w.Header().Set(contentType, jsonContentType)
	w.WriteHeader(http.StatusOK)

	indentResp, err := json.MarshalIndent(resp, " ", " ")
	if err != nil {
		log.Errorf("Error occured when marshalling response: %s", err)
		return
	}
	if w.Write(indentResp); err != nil {
		log.Errorf("Error occured when writing response: %s", err)
		return
	}
}

// HandleStartJobRequest is the handler for manually starting jobs
// /api/v1/job/start/{id}
func HandleStartJobRequest(cache *job.JobCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		j, err := cache.Get(id)
		if err != nil {
			log.Errorf("Error occured when trying to get the job you requested.")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if j == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		j.StopTimer()
		//j.Run(&cache)

		w.WriteHeader(http.StatusNoContent)
	}
}

// HandleDisableJobRequest is the handler for mdisabling jobs
// /api/v1/job/disable/{id}
func HandleDisableJobRequest(cache *job.JobCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		j, err := cache.Get(id)
		if err != nil {
			log.Errorf("Error occured when trying to get the job you requested.")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if j == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		j.Disable()

		w.WriteHeader(http.StatusNoContent)
	}
}

// HandleEnableJobRequest is the handler for enable jobs
// /api/v1/job/enable/{id}
func HandleEnableJobRequest(cache *job.JobCache) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		j, err := cache.Get(id)
		if err != nil {
			log.Errorf("Error occured when trying to get the job you requested.")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if j == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		j.Enable()

		w.WriteHeader(http.StatusNoContent)
	}
}

func StartServer(listenAddr string, cache *job.JobCache, defaultOwner string) error {
	r := mux.NewRouter()
	// Allows for the use for /job as well as /job/
	r.StrictSlash(true)

	// Route for creating a job
	r.HandleFunc(ApiJobPath, HandleAddJob(cache, defaultOwner)).Methods("POST")
	// Route for deleting and getting a job
	r.HandleFunc(ApiJobPath+"{id}/", HandleJobRequest(cache)).Methods("DELETE", "GET")
	// Route for getting job metadata
	r.HandleFunc(ApiJobPath+"meta/{id}/", HandleListJobStatsRequest(cache)).Methods("GET")
	// Route for listing all jobs
	r.HandleFunc(ApiJobPath, HandleListJobsRequest(cache)).Methods("GET")
	// Route for manually start a job
	r.HandleFunc(ApiJobPath+"start/{id}/", HandleStartJobRequest(cache)).Methods("POST")
	// Route for manually stop a job
	r.HandleFunc(ApiJobPath+"stop/{id}/", HandleDisableJobRequest(cache)).Methods("POST")

	return http.ListenAndServe(listenAddr, r)
}
