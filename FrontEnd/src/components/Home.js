import React from "react";
import { useState, useEffect } from "react";
import BeatLoader from "react-spinners/BeatLoader";
import "./styles/Home.css";
import Navbar from "./Navbar";
import Profile from "./Profile";
import { Outlet } from "react-router-dom";
import Aos from "aos";
import "aos/dist/aos.css";
import axios from "axios";

const Home = ({ tasks }) => {
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
    }, 1200);
  }, []);

  useEffect(() => {
    Aos.init({ duration: 1000 });
    
    axios.get('https://task-manager-app-v8af.onrender.com/getUser', { withCredentials: true })
      .then(response => {
        console.log('User:', response.data);
      })
      .catch(error => {
        console.error('Error fetching user:', error);
      });
  }, []);

  return (
    <>
      {loading ? (
        <BeatLoader
          color={"#39A7FF"}
          loading={loading}
          // cssOverride={override}
          size={50}
          aria-label="Loading Spinner"
          data-testid="loader"
        />
      ) : (
        <div className="main-home-container" data-aos="zoom-out">
          <Navbar />
          <Outlet />
          <Profile tasks={tasks} />
        </div>
      )}
    </>
  );
};

export default Home;
