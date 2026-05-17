import React, { useEffect, useRef } from 'react';
import './Cursor.css';

const Cursor = () => {
  const cursorRef = useRef(null);
  const ringRef = useRef(null);
  
  // Position refs for smooth trailing
  const pos = useRef({ x: 0, y: 0 });
  const mouse = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const cursor = cursorRef.current;
    const ring = ringRef.current;
    let requestRef;

    const onMouseMove = (e) => {
      mouse.current.x = e.clientX;
      mouse.current.y = e.clientY;
      // Instant update for the dot
      if (cursor) {
        cursor.style.transform = `translate3d(${e.clientX}px, ${e.clientY}px, 0) translate(-50%, -50%)`;
      }
    };

    const animateRing = () => {
      // Lerp for smooth ring trailing
      pos.current.x += (mouse.current.x - pos.current.x) * 0.15;
      pos.current.y += (mouse.current.y - pos.current.y) * 0.15;
      
      if (ring) {
        ring.style.transform = `translate3d(${pos.current.x}px, ${pos.current.y}px, 0) translate(-50%, -50%)`;
      }
      
      requestRef = requestAnimationFrame(animateRing);
    };

    const onHoverEnter = () => {
      if (cursor) cursor.classList.add('hover');
      if (ring) ring.classList.add('hover');
    };

    const onHoverLeave = () => {
      if (cursor) cursor.classList.remove('hover');
      if (ring) ring.classList.remove('hover');
    };

    // Attach listeners
    document.addEventListener('mousemove', onMouseMove);
    requestRef = requestAnimationFrame(animateRing);

    // Attach hover effects to interactive elements
    const interactiveElements = document.querySelectorAll('a, button, input, .interactive');
    interactiveElements.forEach(el => {
      el.addEventListener('mouseenter', onHoverEnter);
      el.addEventListener('mouseleave', onHoverLeave);
    });

    return () => {
      document.removeEventListener('mousemove', onMouseMove);
      cancelAnimationFrame(requestRef);
      interactiveElements.forEach(el => {
        el.removeEventListener('mouseenter', onHoverEnter);
        el.removeEventListener('mouseleave', onHoverLeave);
      });
    };
  }, []);

  return (
    <>
      <div ref={cursorRef} className="custom-cursor" />
      <div ref={ringRef} className="custom-cursor-ring" />
    </>
  );
};

export default Cursor;
