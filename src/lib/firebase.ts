import { initializeApp } from "firebase/app";
import { 
  getAuth, 
  GoogleAuthProvider, 
  signInWithPopup, 
  signOut, 
  onAuthStateChanged, 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  type User 
} from "firebase/auth";
import { 
  getFirestore, 
  collection, 
  doc, 
  setDoc, 
  getDoc, 
  getDocs, 
  query, 
  orderBy, 
  limit, 
  onSnapshot, 
  addDoc, 
  deleteDoc, 
  updateDoc, 
  getDocFromServer 
} from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyBAe_WHwLZXSxr6wPQmqCEKm8kvQ_Td4-4",
  authDomain: "sentinel-soc-app.firebaseapp.com",
  projectId: "sentinel-soc-app",
  storageBucket: "sentinel-soc-app.firebasestorage.app",
  messagingSenderId: "810100053044",
  appId: "1:810100053044:web:924aa613227a4697daa661",
  measurementId: "G-7J7KVD2RV4"
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();

export { 
  signInWithPopup, 
  signOut, 
  onAuthStateChanged, 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  collection, 
  doc, 
  setDoc, 
  getDoc, 
  getDocs, 
  query, 
  orderBy, 
  limit, 
  onSnapshot, 
  addDoc, 
  deleteDoc, 
  updateDoc, 
  getDocFromServer 
};
export type { User };
