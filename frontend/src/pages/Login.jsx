import React, { useState, useEffect } from "react";
import axios from "axios";
import { FaUser, FaLock } from "react-icons/fa";

const Login = () => {
  const [formData, setFormData] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
  
    if (token) {
      axios
        .get("http://127.0.0.1:8000/api/v1/auth/me", { // ✅ Fix URL
          headers: {
            Authorization: `Bearer ${token}`,
          },
        })
        .then((response) => {
          console.log("User details:", response.data);
          window.location.href = "/dashboard"; // ✅ Redirect if logged in
        })
        .catch((error) => {
          console.error("Session expired or invalid:", error.response?.data);
          localStorage.removeItem("token");
        });
    }
  }, []);
  

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
  
    try {
      const response = await axios.post(
        "http://127.0.0.1:8000/api/v1/auth/login",
        new URLSearchParams({
          username: formData.username.trim().toLowerCase(),  // Ensure correct format
          password: formData.password
        }),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          },
          withCredentials: true, // Allow cookies if needed
        }
      );
  
      console.log("Login Success:", response.data);
      localStorage.setItem("token", response.data.access_token);
  
      // ✅ Ensure we don't push an infinite loop
      window.location.href = "/dashboard";
    } catch (error) {
      console.error("Login failed:", error.response?.data);
      setError(error.response?.data?.detail || "Invalid credentials");
    } finally {
      setLoading(false);
    }
  };
  

  return (
    <div className="flex justify-center items-center min-h-screen bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-lg w-96">
        <h2 className="text-2xl font-semibold text-center mb-6">Login</h2>

        {error && <p className="text-red-500 text-center mb-4">{error}</p>}

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Username Input */}
          <div className="relative">
            <FaUser className="absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              name="username"
              placeholder="Username"
              className="border border-gray-300 rounded w-full p-3 pl-10 focus:ring focus:ring-blue-300 outline-none"
              onChange={handleChange}
              required
            />
          </div>

          {/* Password Input */}
          <div className="relative">
            <FaLock className="absolute left-3 top-3 text-gray-400" />
            <input
              type="password"
              name="password"
              placeholder="Password"
              className="border border-gray-300 rounded w-full p-3 pl-10 focus:ring focus:ring-blue-300 outline-none"
              onChange={handleChange}
              required
            />
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="bg-blue-500 text-white px-4 py-3 w-full rounded-lg font-semibold hover:bg-blue-600 transition"
            disabled={loading}
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <svg
                  className="animate-spin h-5 w-5 mr-2 text-white"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path
                    fill="currentColor"
                    d="M4 12a8 8 0 0116 0"
                  />
                </svg>
                Logging in...
              </span>
            ) : (
              "Login"
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default Login;